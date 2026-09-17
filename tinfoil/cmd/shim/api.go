package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/boot"
	"tinfoil/internal/config"
	"tinfoil/internal/key"
	"tinfoil/internal/legacy"
	"tinfoil/internal/metrics"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpProtocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

type collateralSource interface {
	Current(context.Context) ([]envelope.CollateralEntry, error)
}

// pathMatchesPattern checks if a request path matches a pattern.
// Patterns can be exact matches or use a trailing * for segment-boundary prefix matching.
// Examples:
//   - "/v1/models" matches only "/v1/models"
//   - "/v1/user/*" matches "/v1/user/123", "/v1/user/abc/settings", etc.
func pathMatchesPattern(pattern, path string) bool {
	prefix, wildcard := strings.CutSuffix(pattern, "*")
	if !wildcard {
		return pattern == path
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// pathAllowed checks if the request path matches any of the allowed patterns.
func pathAllowed(allowedPaths []string, path string) bool {
	for _, pattern := range allowedPaths {
		if pathMatchesPattern(pattern, path) {
			return true
		}
	}
	return false
}

func requestedHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	return strings.ToLower(host)
}

// requiresAuth reports whether path requires API key authentication.
// If authenticatedEndpoints is nil (not configured), it defaults to only
// requiring auth for /v1/chat/completions for backwards compatibility.
// If authenticatedEndpoints is an empty slice, no paths require auth.
func requiresAuth(authenticatedEndpoints *[]string, path string) bool {
	if authenticatedEndpoints == nil {
		return path == "/v1/chat/completions"
	}
	return pathAllowed(*authenticatedEndpoints, path)
}

// metricsValidator validates /metrics online-only: the local JWT leg accepts
// any inference-scoped token without consulting the control plane, which would
// bypass its admin-key requirement for /metrics. All other paths use the full
// chain.
type metricsValidator struct {
	online key.Validator
	chain  key.Validator
}

func (v *metricsValidator) Validate(req key.Request) error {
	if req.Path == "/metrics" {
		return v.online.Validate(req)
	}
	return v.chain.Validate(req)
}

// extractBearerToken returns the token portion of an Authorization header,
// accepting any capitalization of the "Bearer" scheme.
func extractBearerToken(header string) string {
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

// writeValidationFailure maps a credential validation failure onto the
// client-facing error for its status. A 403 is a valid credential that lacks
// permission, which is distinct from a 401's bad or unknown credential.
func writeValidationFailure(w http.ResponseWriter, err error) {
	var validationErr *key.ValidationError
	if !errors.As(err, &validationErr) {
		writeAPIError(w, errServer)
		return
	}

	switch validationErr.StatusCode {
	case http.StatusUnauthorized:
		writeAPIError(w, errInvalidAPIKey)
	case http.StatusForbidden:
		writeAPIError(w, errInsufficientPermissions)
	case http.StatusPaymentRequired:
		writeAPIError(w, errQuotaExceeded)
	case http.StatusTooManyRequests:
		writeAPIError(w, errRateLimited)
	default:
		writeAPIError(w, errServer)
	}
}

func corsMiddleware(config *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Allow only configured origins
			if len(config.OriginDomains) > 0 && !slices.Contains(config.OriginDomains, origin) {
				// CORS origin not allowed
				writeAPIError(w, errOriginNotAllowed)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin") // cache
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, HEAD, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", "Ehbp-Encapsulated-Key, Ehbp-Response-Nonce, Content-Type, Tinfoil-Pt")

			// Echo requested headers or use a safe default
			reqHdr := r.Header.Get("Access-Control-Request-Headers")
			if reqHdr == "" {
				reqHdr = "Authorization, Content-Type, Ehbp-Encapsulated-Key"
			}
			w.Header().Set("Access-Control-Allow-Headers", reqHdr)

			if r.Method == http.MethodOptions {
				// CORS preflight
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// CORS allowed
		}

		next.ServeHTTP(w, r)
	})
}

func NewShimServer(
	validator key.Validator,
	rateLimiter *RateLimiter,
	att *legacy.Document,
	identityBody tinfoilattestation.BodyV2,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	collateralSource collateralSource,
	config *config.Config,
	externalConfig *config.ExternalConfig,
	upstreamAddr string,
	tunnelTargets map[string]bool,
) http.Handler {
	ehbpMiddleware := ehbpIdentity.Middleware()
	mux := http.NewServeMux()

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host

			req.URL.Scheme = "http"
			req.URL.Host = upstreamAddr
			req.Header.Set("Host", "localhost")
			req.Host = "localhost"
			req.Header.Del(ehbpProtocol.EncapsulatedKeyHeader)

			// Forward original host and protocol to the upstream
			req.Header.Del("Forwarded")
			req.Header.Del("X-Forwarded-Host")
			req.Header.Set("Forwarded", fmt.Sprintf("host=\"%s\"", originalHost))
			req.Header.Set("X-Forwarded-Host", originalHost)

			// proxied
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Access-Control-Allow-Origin")
			res.Header.Del(ehbpProtocol.ResponseNonceHeader)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error: %v", err)
			writeAPIError(w, errUpstreamUnreachable)
		},
	}

	// A CONNECT carries no path for requiresAuth to match, so it always needs a key.
	authorize := func(w http.ResponseWriter, r *http.Request) bool {
		apiKey := extractBearerToken(r.Header.Get("Authorization"))
		if validator != nil && (r.Method == http.MethodConnect || requiresAuth(config.AuthenticatedEndpoints, r.URL.Path)) {
			if len(apiKey) == 0 {
				writeAPIError(w, errAPIKeyRequired)
				return false
			}

			validationReq := key.Request{
				APIKey:        apiKey,
				Domain:        strings.ToLower(externalConfig.Env["DOMAIN"]),
				RequestedHost: requestedHost(r),
				Path:          r.URL.Path,
			}

			if err := validator.Validate(validationReq); err != nil {
				log.Printf("Warning: failed to validate API key: %v", err)
				writeValidationFailure(w, err)
				return false
			}
		}

		if rateLimiter != nil {
			if apiKey == "" {
				writeAPIError(w, errAPIKeyRequired)
				return false
			}
			limiter := rateLimiter.Limit(apiKey)
			if reservation := limiter.Reserve(); !reservation.OK() || reservation.Delay() > 0 {
				// Reserve reports how long until a token frees up; cancel so
				// the rejected request does not consume it.
				delay := reservation.Delay()
				reservation.Cancel()
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(delay)))
				writeAPIError(w, errRateLimited)
				return false
			}
		}
		return true
	}

	proxyHandler := ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r) {
			return
		}
		proxy.ServeHTTP(w, r)
	}))

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(config.Paths) > 0 && !pathAllowed(config.Paths, r.URL.Path) {
			writeAPIError(w, errNotFound)
			return
		}
		proxyHandler.ServeHTTP(w, r)
	}))

	registerObservabilityHandlers(mux, ehbpMiddleware, att, identityBody, expectedGPUs, ehbpIdentity, tlsCert, collateralSource, externalConfig)

	// Fail closed: an authenticated deployment with no validator must not tunnel.
	if config.Authenticated && validator == nil {
		tunnelTargets = nil
	}
	return wrapShimMux(config, att, tunnels(tunnelTargets, authorize, mux))
}

func NewObservabilityServer(
	att *legacy.Document,
	identityBody tinfoilattestation.BodyV2,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	collateralSource collateralSource,
	config *config.Config,
	externalConfig *config.ExternalConfig,
) http.Handler {
	ehbpMiddleware := ehbpIdentity.Middleware()
	mux := http.NewServeMux()
	registerObservabilityHandlers(mux, ehbpMiddleware, att, identityBody, expectedGPUs, ehbpIdentity, tlsCert, collateralSource, externalConfig)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeWorkloadUnavailable(w)
	})
	return wrapShimMux(config, att, mux)
}

func wrapShimMux(config *config.Config, att *legacy.Document, mux http.Handler) http.Handler {
	globalMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Tinfoil-Pt", string(att.Format))
			next.ServeHTTP(w, r)
		})
	}
	return corsMiddleware(config, globalMiddleware(mux))
}

func registerObservabilityHandlers(
	mux *http.ServeMux,
	ehbpMiddleware func(http.Handler) http.Handler,
	att *legacy.Document,
	identityBody tinfoilattestation.BodyV2,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	collateralSource collateralSource,
	externalConfig *config.ExternalConfig,
) {
	mux.Handle("/.well-known/tinfoil-attestation", ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Fresh v3 attestation with nonce: ?nonce=<64 hex chars>
		if nonceHex := r.URL.Query().Get("nonce"); nonceHex != "" {
			nonce, err := hex.DecodeString(nonceHex)
			if err != nil || len(nonce) != 32 {
				writeAPIError(w, errInvalidNonce)
				return
			}
			var nonce32 [32]byte
			copy(nonce32[:], nonce)
			var collateral []envelope.CollateralEntry
			if collateralSource != nil {
				collateral, err = collateralSource.Current(r.Context())
				if err != nil {
					log.Printf("Attestation collateral unavailable: %v", err)
					writeAPIError(w, errCollateralUnavailable)
					return
				}
			}
			deviceEvidence, err := tinfoilattestation.CollectDeviceEvidence(nonce32, expectedGPUs)
			if err != nil {
				log.Printf("Device evidence collection failed for %d expected GPU(s): %v", expectedGPUs, err)
				writeAPIError(w, errGPUEvidenceUnavailable)
				return
			}

			fresh, err := tinfoilattestation.BuildAttestation(
				identityBody.TLSKeyFP,
				identityBody.HPKEKey,
				nonce,
				deviceEvidence,
				collateral,
			)
			if err != nil {
				log.Printf("Fresh attestation failed: %v", err)
				writeAPIError(w, errAttestationBuildFailed)
				return
			}

			json.NewEncoder(w).Encode(fresh)
			return
		}

		// Legacy (no nonce)
		json.NewEncoder(w).Encode(att)
	})))

	mux.HandleFunc("/.well-known/tinfoil-certificate", func(w http.ResponseWriter, r *http.Request) {
		if tlsCert == nil || len(tlsCert.Certificate) == 0 {
			http.Error(w, "Certificate not available", http.StatusServiceUnavailable)
			return
		}

		// Encode the leaf certificate as PEM
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCert.Certificate[0],
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"certificate": string(certPEM),
		})
	})

	mux.HandleFunc("/.well-known/tinfoil-boot-stages", func(w http.ResponseWriter, r *http.Request) {
		state, err := boot.Load()
		if err != nil {
			http.Error(w, "boot state not available", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})

	mux.HandleFunc("/.well-known/tinfoil-metrics", metrics.HandleMetrics(externalConfig))
	mux.HandleFunc("/.well-known/metrics", metrics.HandlePrometheusMetrics(&externalConfig.Metadata, externalConfig.MetricsAPIKey))
	mux.HandleFunc("/.well-known/tinfoil-containers", containersHandler())
	mux.HandleFunc(ehbpProtocol.KeysPath, ehbpIdentity.ConfigHandler)
}

// writeWorkloadUnavailable answers requests that arrive before the workload
// proxy is serving. A failed boot is permanent for this VM and must not read
// as a transient; a pending boot invites a retry. The boot state is attached
// so operators can see which stage is at fault.
func writeWorkloadUnavailable(w http.ResponseWriter) {
	apiErr := errServiceStarting
	var state any
	if s, err := boot.Load(); err == nil {
		state = s
		if s.HasFailed() {
			apiErr = errServiceFailed
		}
	}
	body := map[string]any{"error": apiErr.envelope().Error}
	if state != nil {
		body["boot"] = state
	}

	w.Header().Set("Content-Type", "application/json")
	if apiErr.code == errCodeServiceStarting {
		w.Header().Set("Retry-After", strconv.Itoa(serviceStartingRetryAfterSeconds))
	}
	w.WriteHeader(apiErr.status)
	json.NewEncoder(w).Encode(body)
}
