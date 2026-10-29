package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/boot"
	"tinfoil/internal/config"
	"tinfoil/internal/metrics"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpProtocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"
)

const (
	attestationFormatHeader = "Tinfoil-Pt"
	attestationPath         = "/.well-known/tinfoil-attestation"
	attestationV3Path       = attestationPath + "/v3"
)

type collateralSource interface {
	Current(context.Context) (wire.Response, error)
}

func NewShimServer(
	identityBody tinfoilattestation.Identity,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	collateralSource collateralSource,
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
			// Preserve the caller's Host for workload authorization.
			req.Host = originalHost
			req.Header.Del(ehbpProtocol.EncapsulatedKeyHeader)

			// Forward original host and protocol to the upstream
			req.Header.Del("Forwarded")
			req.Header.Del("X-Forwarded-Host")
			req.Header.Set("Forwarded", fmt.Sprintf("host=\"%s\"", originalHost))
			req.Header.Set("X-Forwarded-Host", originalHost)

			// proxied
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del(ehbpProtocol.ResponseNonceHeader)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error: %v", err)
			writeAPIError(w, errUpstreamUnreachable)
		},
	}

	mux.Handle("/", ehbpMiddleware(&proxy))

	registerObservabilityHandlers(mux, ehbpMiddleware, identityBody, expectedGPUs, ehbpIdentity, tlsCert, collateralSource, externalConfig)

	return wrapShimMux(tunnels(tunnelTargets, mux))
}

func NewObservabilityServer(
	identityBody tinfoilattestation.Identity,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	collateralSource collateralSource,
	externalConfig *config.ExternalConfig,
) http.Handler {
	ehbpMiddleware := ehbpIdentity.Middleware()
	mux := http.NewServeMux()
	registerObservabilityHandlers(mux, ehbpMiddleware, identityBody, expectedGPUs, ehbpIdentity, tlsCert, collateralSource, externalConfig)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeWorkloadUnavailable(w)
	})
	return wrapShimMux(mux)
}

func wrapShimMux(mux http.Handler) http.Handler {
	globalMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(attestationFormatHeader, envelope.AttestationV3Format)
			next.ServeHTTP(w, r)
		})
	}
	return transportCORS(globalMiddleware(mux))
}

func registerObservabilityHandlers(
	mux *http.ServeMux,
	ehbpMiddleware func(http.Handler) http.Handler,
	identityBody tinfoilattestation.Identity,
	expectedGPUs int,
	ehbpIdentity *identity.Identity,
	tlsCert *tls.Certificate,
	collateralSource collateralSource,
	externalConfig *config.ExternalConfig,
) {
	attestationHandler := ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		query, err := url.ParseQuery(r.URL.RawQuery)
		nonces := query["nonce"]
		if err != nil || len(query) != 1 || len(nonces) != 1 || nonces[0] == "" {
			writeAPIError(w, errInvalidNonce)
			return
		}

		// Fresh v3 attestation with nonce: ?nonce=<64 hex chars>
		nonce, err := hex.DecodeString(nonces[0])
		if err != nil || len(nonce) != envelope.NonceSize {
			writeAPIError(w, errInvalidNonce)
			return
		}
		var nonce32 [envelope.NonceSize]byte
		copy(nonce32[:], nonce)
		var collateral wire.Response
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
			identityBody.CryptoMaterial(),
			nonce,
			deviceEvidence,
			collateral,
		)
		if err != nil {
			log.Printf("Fresh attestation failed: %v", err)
			writeAPIError(w, errAttestationBuildFailed)
			return
		}

		w.Header().Set(attestationFormatHeader, envelope.AttestationV3Format)
		json.NewEncoder(w).Encode(fresh)
	}))
	mux.Handle(attestationPath, metrics.ObserveAttestation(metrics.AttestationEndpointUnversioned, attestationHandler))
	versionedAttestationHandler := metrics.ObserveAttestation(metrics.AttestationEndpointV3, attestationHandler)
	mux.Handle("GET "+attestationV3Path, versionedAttestationHandler)
	mux.Handle("GET "+attestationV3Path+"/{$}", versionedAttestationHandler)
	mux.HandleFunc(attestationPath+"/", func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, errNotFound)
	})

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
	mux.HandleFunc(shutdownPath, shutdownHandler(externalConfig.ShutdownToken, signalInit))
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

func transportCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		transport := r.URL.Path == ehbpProtocol.KeysPath || r.URL.Path == attestationPath || strings.HasPrefix(r.URL.Path, attestationPath+"/")
		switch r.URL.Path {
		case "/.well-known/tinfoil-certificate", "/.well-known/tinfoil-boot-stages", "/.well-known/tinfoil-metrics", "/.well-known/metrics", "/.well-known/tinfoil-containers":
			transport = true
		}
		if origin := r.Header.Get("Origin"); transport && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", "Ehbp-Encapsulated-Key, Ehbp-Response-Nonce, Content-Type, Tinfoil-Pt, Retry-After")
			headers := r.Header.Get("Access-Control-Request-Headers")
			if headers == "" {
				headers = "Authorization, Content-Type, Ehbp-Encapsulated-Key"
			}
			w.Header().Set("Access-Control-Allow-Headers", headers)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
