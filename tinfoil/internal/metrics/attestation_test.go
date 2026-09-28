package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	"tinfoil/internal/legacy"
)

func TestAttestationRequestMetrics(t *testing.T) {
	m := newAttestationMetrics()
	for _, test := range []struct {
		endpoint, format, sdk, version string
		status                         int
	}{
		{AttestationEndpointUnversioned, string(legacy.SevGuestV2), "", "", http.StatusOK},
		{AttestationEndpointUnversioned, envelope.AttestationV3Format, "tinfoil-go", "v0.15.7", http.StatusOK},
		{AttestationEndpointV3, envelope.AttestationV3Format, "tinfoil-go", "0.15.7", http.StatusOK},
		{AttestationEndpointV3, string(legacy.SevGuestV2), "tinfoil-go", "0.15.7", http.StatusBadRequest},
		{AttestationEndpointV3, string(legacy.SevGuestV2), "tinfoil-go", "0.15.7", http.StatusServiceUnavailable},
	} {
		handler := m.observe(test.endpoint, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(attestationFormatHeader, test.format)
			w.WriteHeader(test.status)
			fmt.Fprint(w, "response")
		}))
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set(sdkNameHeader, test.sdk)
		request.Header.Set(sdkVersionHeader, test.version)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, test.status, response.Code)
		require.Equal(t, "response", response.Body.String())
	}
	require.NoError(t, testutil.CollectAndCompare(m.requests, strings.NewReader(`
# HELP tfshim_attestation_requests_total Attestation HTTP requests by endpoint, served format, self-reported SDK, and response result; does not indicate client verification success.
# TYPE tfshim_attestation_requests_total counter
tfshim_attestation_requests_total{attestation_version="v2",endpoint="unversioned",result="served",sdk="unknown",sdk_version="unknown"} 1
tfshim_attestation_requests_total{attestation_version="v3",endpoint="unversioned",result="served",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="v3",endpoint="v3",result="served",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="none",endpoint="v3",result="client_error",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="none",endpoint="v3",result="server_error",sdk="tinfoil-go",sdk_version="0.15.7"} 1
`)))
}

func TestAttestationSDKLabels(t *testing.T) {
	m := newAttestationMetrics()
	for _, test := range []struct {
		name, version string
		want          sdkIdentity
	}{
		{"", "", sdkIdentity{"unknown", "unknown"}},
		{"custom-client", "1.0.0", sdkIdentity{"unknown", "unknown"}},
		{"tinfoil-go", "", sdkIdentity{"tinfoil-go", "unknown"}},
		{"tinfoil-go", "invalid", sdkIdentity{"tinfoil-go", "unknown"}},
		{"tinfoil-go", strings.Repeat("1", maxSDKVersionLength+1), sdkIdentity{"tinfoil-go", "unknown"}},
		{"tinfoil-go", "devel", sdkIdentity{"tinfoil-go", "devel"}},
		{"tinfoil-go", "unknown", sdkIdentity{"tinfoil-go", "unknown"}},
		{"tinfoil-go", "v0.15.7", sdkIdentity{"tinfoil-go", "0.15.7"}},
		{"tinfoil-js", "1.2.3-beta.1", sdkIdentity{"tinfoil-js", "1.2.3-beta.1"}},
		{"tinfoil-python", "1.2.3", sdkIdentity{"tinfoil-python", "1.2.3"}},
		{"@tinfoilsh/verifier", "1.2.1", sdkIdentity{"@tinfoilsh/verifier", "1.2.1"}},
	} {
		headers := make(http.Header)
		headers.Set(sdkNameHeader, test.name)
		headers.Set(sdkVersionHeader, test.version)
		require.Equal(t, test.want, m.sdkLabels(headers))
	}
}

func TestAttestationMetricsBoundConcurrentVersions(t *testing.T) {
	m := newAttestationMetrics()
	handler := m.observe(AttestationEndpointV3, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(attestationFormatHeader, envelope.AttestationV3Format)
		w.WriteHeader(http.StatusOK)
	}))
	requestVersion := func(version string) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set(sdkNameHeader, "tinfoil-go")
		request.Header.Set(sdkVersionHeader, version)
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	requestVersion("0.15.7")
	var wg sync.WaitGroup
	const requestCount = 2 * maxSDKIdentities
	for i := range requestCount {
		wg.Go(func() { requestVersion(fmt.Sprintf("1.0.%d", i)) })
	}
	wg.Wait()
	requestVersion("0.15.7")

	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(m.requests)
	families, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	require.Len(t, families[0].Metric, maxSDKIdentities+1)
	var total float64
	for _, metric := range families[0].Metric {
		total += metric.GetCounter().GetValue()
	}
	require.Equal(t, float64(requestCount+2), total)
	require.Equal(t, float64(2), testutil.ToFloat64(m.requests.WithLabelValues("v3", "v3", "tinfoil-go", "0.15.7", "served")))
	require.Equal(t, float64(requestCount-maxSDKIdentities+1), testutil.ToFloat64(m.requests.WithLabelValues("v3", "v3", "tinfoil-go", "other", "served")))
}
