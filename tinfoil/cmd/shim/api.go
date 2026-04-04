package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"

	"tinfoil/internal/acpi"
	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/boot"
	"tinfoil/internal/config"
	"tinfoil/internal/key"
	"tinfoil/internal/key/online"
	"tinfoil/internal/metrics"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpProtocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// pathMatchesPattern checks if a request path matches a pattern.
// Patterns can be exact matches or use a trailing * for prefix matching.
// Examples:
//   - "/v1/models" matches only "/v1/models"
//   - "/v1/user/*" matches "/v1/user/123", "/v1/user/abc/settings", etc.
func pathMatchesPattern(pattern, path string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
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
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
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
	gpuCount int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	config *config.Config,
	externalConfig *config.ExternalConfig,
) http.Handler {
	ehbpMiddleware := ehbpIdentity.Middleware()
	mux := http.NewServeMux()

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host

			req.URL.Scheme = "http"
			req.URL.Host = fmt.Sprintf("127.0.0.1:%d", config.UpstreamPort)
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

	globalMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Tinfoil-Pt", string(att.Format))
			next.ServeHTTP(w, r)
		})
	}

	proxyHandler := ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if validator != nil && requiresAuth(config.AuthenticatedEndpoints, r.URL.Path) {
			if len(apiKey) == 0 {
				writeJSONError(w, errMsgAPIKeyRequired, errTypeInvalidRequest, http.StatusUnauthorized)
				return
			}

			if err := validator.Validate(apiKey); err != nil {
				log.Printf("Warning: failed to validate API key: %v", err)
				var validationErr *online.ValidationError
				if errors.As(err, &validationErr) {
					// Pass through the JSON error body from the control plane
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(validationErr.StatusCode)
					fmt.Fprint(w, validationErr.Message)
				} else {
					writeJSONError(w, errMsgServerError, errTypeServer, http.StatusInternalServerError)
				}
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

	mux.Handle("/.well-known/tinfoil-attestation", ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// V3 attestation — always fresh, with verifier-supplied or random nonce
		if r.URL.Query().Get("v") == "3" {
			var nonce []byte
			if nonceHex := r.URL.Query().Get("nonce"); nonceHex != "" {
				var err error
				nonce, err = hex.DecodeString(nonceHex)
				if err != nil || len(nonce) != 32 {
					writeJSONError(w, "Invalid nonce: must be exactly 32 bytes (64 hex chars)", errTypeInvalidRequest, http.StatusBadRequest)
					return
				}
			} else {
				var err error
				nonce, err = tinfoilattestation.RandomNonce()
				if err != nil {
					writeJSONError(w, "Failed to generate nonce", errTypeServer, http.StatusInternalServerError)
					return
				}
			}

			// Collect fresh GPU and NVSwitch evidence with nonce (skip if no hardware)
			var gpuJSON, nvswitchJSON json.RawMessage
			var nonce32 [32]byte
			copy(nonce32[:], nonce)
			if gpuCount > 0 {
				gpuEvidence, err := tinfoilattestation.CollectGPUEvidence(nonce32)
				if err != nil {
					log.Printf("GPU evidence collection failed (non-fatal): %v", err)
				} else if len(gpuEvidence.Evidences) > 0 {
					gpuJSON, _ = json.Marshal(gpuEvidence)
				}
				if gpuCount >= 8 {
					nvswitchJSON, err = tinfoilattestation.CollectNVSwitchEvidence(nonce32)
					if err != nil {
						log.Printf("NVSwitch evidence collection failed (non-fatal): %v", err)
						nvswitchJSON = nil
					}
				}
			}

			// Build signed V3: GPU + NVSwitch evidence hashes bound into CPU REPORT_DATA
			v3, err := tinfoilattestation.BuildV3(
				identityBody.TLSKeyFP,
				identityBody.HPKEKey,
				nonce,
				gpuJSON,
				nvswitchJSON,
				tlsCert,
			)
			if err != nil {
				log.Printf("V3 attestation build failed: %v", err)
				writeJSONError(w, "Failed to build attestation", errTypeServer, http.StatusInternalServerError)
				return
			}

			json.NewEncoder(w).Encode(v3)
			return
		}

		// Legacy V2
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
	mux.HandleFunc("/.well-known/tinfoil-acpi", acpi.HandleQemuACPI(config, externalConfig))
	mux.HandleFunc("/.well-known/metrics", metrics.HandlePrometheusMetrics(&externalConfig.Metadata, externalConfig.MetricsAPIKey))
	mux.HandleFunc(ehbpProtocol.KeysPath, ehbpIdentity.ConfigHandler)

	return corsMiddleware(config, globalMiddleware(mux))
}
