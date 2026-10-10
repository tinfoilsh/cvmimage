package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	envelope "github.com/tinfoilsh/tinfoil-go/document"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
)

func TestAttestationMetricsThroughShim(t *testing.T) {
	const metricsPath = "/.well-known/metrics"
	const metricsKey = "test-metrics-key"
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "observability", true: "shim"}[ready], func(t *testing.T) {
			id, err := identity.NewIdentity()
			require.NoError(t, err)
			ext := &config.ExternalConfig{MetricsAPIKey: metricsKey}
			ext.Metadata.ID = "test-enclave"
			var handler http.Handler
			if ready {
				handler = NewShimServer(nil, nil, tinfoilattestation.BodyV2{}, 0, id, nil, errorCollateralSource{}, &config.Config{}, ext, "127.0.0.1:9999", nil)
			} else {
				handler = NewObservabilityServer(tinfoilattestation.BodyV2{}, 0, id, nil, errorCollateralSource{}, &config.Config{}, ext)
			}
			unauthorized := httptest.NewRecorder()
			handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, metricsPath, nil))
			require.Equal(t, http.StatusUnauthorized, unauthorized.Code)

			counter := func(endpoint, version, sdk, sdkVersion, result string) float64 {
				request := httptest.NewRequest(http.MethodGet, metricsPath, nil)
				request.Header.Set("Authorization", "Bearer "+metricsKey)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				parser := expfmt.NewTextParser(model.UTF8Validation)
				families, err := parser.TextToMetricFamilies(response.Body)
				require.NoError(t, err)
				for _, metric := range families["tfshim_attestation_requests_total"].GetMetric() {
					labels := make(map[string]string)
					for _, label := range metric.Label {
						labels[label.GetName()] = label.GetValue()
					}
					if labels["endpoint"] == endpoint && labels["attestation_version"] == version && labels["sdk"] == sdk && labels["sdk_version"] == sdkVersion && labels["client_family"] == "go" && labels["result"] == result {
						require.Equal(t, "test-enclave", labels["id"])
						return metric.GetCounter().GetValue()
					}
				}
				return 0
			}
			for _, test := range []struct {
				path, endpoint, version, sdk, sdkVersion, result string
				status                                           int
			}{
				{attestationPath, "unversioned", "none", "unknown", "unknown", "client_error", http.StatusBadRequest},
				{attestationPath, "unversioned", "none", "tinfoil-go", "0.15.7", "client_error", http.StatusBadRequest},
				{attestationV3Path, "v3", "none", "tinfoil-go", "0.15.7", "client_error", http.StatusBadRequest},
				{attestationV3Path + "/", "v3", "none", "tinfoil-go", "0.15.7", "client_error", http.StatusBadRequest},
				{attestationPath + "?nonce=" + strings.Repeat("00", envelope.NonceSize), "unversioned", "none", "tinfoil-go", "0.15.7", "server_error", http.StatusServiceUnavailable},
				{attestationV3Path + "?nonce=" + strings.Repeat("00", envelope.NonceSize), "v3", "none", "tinfoil-go", "0.15.7", "server_error", http.StatusServiceUnavailable},
			} {
				before := counter(test.endpoint, test.version, test.sdk, test.sdkVersion, test.result)
				request := httptest.NewRequest(http.MethodGet, test.path, nil)
				request.Header.Set("User-Agent", "Go-http-client/1.1")
				if test.sdk != "unknown" {
					request.Header.Set("Tinfoil-SDK", test.sdk)
					request.Header.Set("Tinfoil-SDK-Version", test.sdkVersion)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				require.Equal(t, test.status, response.Code, response.Body.String())
				for range 2 {
					require.Equal(t, before+1, counter(test.endpoint, test.version, test.sdk, test.sdkVersion, test.result))
				}
			}
		})
	}
}

func TestLocalConfigStatusRequiresMetricsKey(t *testing.T) {
	const metricsKey = "private-metrics-key"
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	for _, ready := range []bool{false, true} {
		for _, key := range []string{"", metricsKey} {
			ext := &config.ExternalConfig{MetricsAPIKey: key}
			ext.Metadata.ConfigSource = config.SourceLocal
			var handler http.Handler
			if ready {
				handler = NewShimServer(nil, nil, tinfoilattestation.BodyV2{}, 0, id, nil, errorCollateralSource{}, &config.Config{}, ext, "127.0.0.1:9999", nil)
			} else {
				handler = NewObservabilityServer(tinfoilattestation.BodyV2{}, 0, id, nil, errorCollateralSource{}, &config.Config{}, ext)
			}
			for _, path := range []string{"/.well-known/tinfoil-containers", "/.well-known/tinfoil-boot-stages", "/.well-known/tinfoil-metrics", "/.well-known/metrics"} {
				for _, token := range []string{"", "wrong-key"} {
					request := httptest.NewRequest(http.MethodGet, path, nil)
					if token != "" {
						request.Header.Set("Authorization", "Bearer "+token)
					}
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					require.Equal(t, http.StatusUnauthorized, response.Code, path)
				}
			}
			request := httptest.NewRequest(http.MethodGet, "/.well-known/metrics", nil)
			request.Header.Set("Authorization", "Bearer "+metricsKey)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if key == "" {
				require.Equal(t, http.StatusUnauthorized, response.Code)
			} else {
				require.Equal(t, http.StatusOK, response.Code)
			}
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, attestationV3Path, nil))
			require.Equal(t, http.StatusBadRequest, response.Code)
		}
	}
}
