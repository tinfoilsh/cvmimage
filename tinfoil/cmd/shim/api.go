package main

import (
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
	"strings"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/boot"
	"tinfoil/internal/config"
	"tinfoil/internal/key"
	"tinfoil/internal/metrics"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpProtocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

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

// OpenAI-compatible error type strings returned in API error responses.
const (
	errTypeInvalidRequest    = "invalid_request_error"
	errTypeInsufficientQuota = "insufficient_quota"
	errTypeServer            = "server_error"
)

// Client-facing error messages, aligned with OpenAI's standard error messages
// where applicable. See https://platform.openai.com/docs/guides/error-codes
const (
	errMsgAPIKeyRequired = "API key is required."
	errMsgInvalidAPIKey  = "Incorrect API key provided."
	errMsgQuotaExceeded  = "Insufficient quota."
	errMsgRateLimited    = "Rate limit reached for requests."
	errMsgServerError    = "The server had an error while processing your request."
)

// writeJSONError writes an OpenAI-compatible JSON error response.
func writeJSONError(w http.ResponseWriter, message string, errorType string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"message": message,
			"type":    errorType,
		},
	})
}

func writeValidationFailure(w http.ResponseWriter, err error) {
	var validationErr *key.ValidationError
	if !errors.As(err, &validationErr) {
		writeJSONError(w, errMsgServerError, errTypeServer, http.StatusInternalServerError)
		return
	}

	switch validationErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		writeJSONError(w, errMsgInvalidAPIKey, errTypeInvalidRequest, validationErr.StatusCode)
	case http.StatusPaymentRequired:
		writeJSONError(w, errMsgQuotaExceeded, errTypeInsufficientQuota, validationErr.StatusCode)
	case http.StatusTooManyRequests:
		writeJSONError(w, errMsgRateLimited, errTypeInsufficientQuota, validationErr.StatusCode)
	default:
		writeJSONError(w, errMsgServerError, errTypeServer, http.StatusInternalServerError)
	}
}

func corsMiddleware(config *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Allow only configured origins
			if len(config.OriginDomains) > 0 && !slices.Contains(config.OriginDomains, origin) {
				// CORS origin not allowed
				writeJSONError(w, "CORS origin not allowed.", errTypeInvalidRequest, http.StatusForbidden)
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
	att *attestation.Document,
	identityBody tinfoilattestation.BodyV2,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	config *config.Config,
	externalConfig *config.ExternalConfig,
	upstreamAddr string,
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
		Transport: &streamTransport{
			base: http.DefaultTransport,
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Access-Control-Allow-Origin")
			res.Header.Del(ehbpProtocol.ResponseNonceHeader)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error: %v", err)
			writeJSONError(w, errMsgServerError, errTypeServer, http.StatusBadGateway)
		},
	}

	proxyHandler := ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := extractBearerToken(r.Header.Get("Authorization"))
		if validator != nil && requiresAuth(config.AuthenticatedEndpoints, r.URL.Path) {
			if len(apiKey) == 0 {
				writeJSONError(w, errMsgAPIKeyRequired, errTypeInvalidRequest, http.StatusUnauthorized)
				return
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
				return
			}
		}

		if rateLimiter != nil {
			if apiKey == "" {
				writeJSONError(w, errMsgAPIKeyRequired, errTypeInvalidRequest, http.StatusUnauthorized)
				return
			}
			limiter := rateLimiter.Limit(apiKey)
			if !limiter.Allow() {
				writeJSONError(w, errMsgRateLimited, errTypeInvalidRequest, http.StatusTooManyRequests)
				return
			}
		}

		proxy.ServeHTTP(w, r)
	}))

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(config.Paths) > 0 && !pathAllowed(config.Paths, r.URL.Path) {
			writeJSONError(w, "Not found.", errTypeInvalidRequest, http.StatusNotFound)
			return
		}
		proxyHandler.ServeHTTP(w, r)
	}))

	registerObservabilityHandlers(mux, ehbpMiddleware, att, identityBody, expectedGPUs, ehbpIdentity, tlsCert, externalConfig)

	return wrapShimMux(config, att, mux)
}

func NewObservabilityServer(
	att *attestation.Document,
	identityBody tinfoilattestation.BodyV2,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	config *config.Config,
	externalConfig *config.ExternalConfig,
) http.Handler {
	ehbpMiddleware := ehbpIdentity.Middleware()
	mux := http.NewServeMux()
	registerObservabilityHandlers(mux, ehbpMiddleware, att, identityBody, expectedGPUs, ehbpIdentity, tlsCert, externalConfig)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeWorkloadUnavailable(w)
	})
	return wrapShimMux(config, att, mux)
}

func wrapShimMux(config *config.Config, att *attestation.Document, mux *http.ServeMux) http.Handler {
	globalMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Tinfoil-Pt", string(att.Format))
			next.ServeHTTP(w, r)
		})
	}
	return corsMiddleware(config, globalMiddleware(mux))
}

func requiresNVSwitchEvidence(expectedGPUs int, gpuEvidence *tinfoilattestation.GPUEvidenceCollection) bool {
	return expectedGPUs == 8 && gpuEvidence.HasArch(tinfoilattestation.GPUArchHopper)
}

func registerObservabilityHandlers(
	mux *http.ServeMux,
	ehbpMiddleware func(http.Handler) http.Handler,
	att *attestation.Document,
	identityBody tinfoilattestation.BodyV2,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	externalConfig *config.ExternalConfig,
) {
	mux.Handle("/.well-known/tinfoil-attestation", ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Fresh attestation with nonce: ?nonce=<64 hex chars>
		if nonceHex := r.URL.Query().Get("nonce"); nonceHex != "" {
			nonce, err := hex.DecodeString(nonceHex)
			if err != nil || len(nonce) != 32 {
				writeJSONError(w, "Invalid nonce: must be exactly 32 bytes (64 hex chars)", errTypeInvalidRequest, http.StatusBadRequest)
				return
			}

			var gpuJSON, nvswitchJSON json.RawMessage
			var nonce32 [32]byte
			copy(nonce32[:], nonce)
			if expectedGPUs > 0 {
				gpuEvidence, err := tinfoilattestation.CollectGPUEvidence(nonce32)
				if err != nil {
					log.Printf("GPU evidence collection failed for %d expected GPU(s): %v", expectedGPUs, err)
					writeJSONError(w, "GPU attestation evidence unavailable", errTypeServer, http.StatusInternalServerError)
					return
				}
				if got := len(gpuEvidence.Evidences); got != expectedGPUs {
					log.Printf("GPU evidence count mismatch: expected %d, got %d", expectedGPUs, got)
					writeJSONError(w, "GPU attestation evidence incomplete", errTypeServer, http.StatusInternalServerError)
					return
				}
				gpuJSON, _ = json.Marshal(gpuEvidence)
				if requiresNVSwitchEvidence(expectedGPUs, gpuEvidence) {
					nvswitchJSON, err = tinfoilattestation.CollectNVSwitchEvidence(nonce32)
					if err != nil {
						log.Printf("NVSwitch evidence collection failed: %v", err)
						writeJSONError(w, "NVSwitch attestation evidence unavailable", errTypeServer, http.StatusInternalServerError)
						return
					}
				}
			}

			fresh, err := tinfoilattestation.BuildAttestation(
				identityBody.TLSKeyFP,
				identityBody.HPKEKey,
				nonce,
				gpuJSON,
				nvswitchJSON,
				tlsCert,
			)
			if err != nil {
				log.Printf("Fresh attestation failed: %v", err)
				writeJSONError(w, "Failed to build attestation", errTypeServer, http.StatusInternalServerError)
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

func writeWorkloadUnavailable(w http.ResponseWriter) {
	status := "pending"
	var state any
	if s, err := boot.Load(); err == nil {
		state = s
		if s.HasFailed() {
			status = "failed"
		}
	}
	body := map[string]any{
		"error": map[string]any{
			"message": "Workload proxy is not ready.",
			"type":    errTypeServer,
			"status":  status,
		},
	}
	if state != nil {
		body["boot"] = state
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(w).Encode(body)
}
