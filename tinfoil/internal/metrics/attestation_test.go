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
		endpoint, format, sdk, version, userAgent string
		status                                    int
	}{
		{AttestationEndpointUnversioned, string(legacy.SevGuestV2), "", "", "Go-http-client/1.1", http.StatusOK},
		{AttestationEndpointUnversioned, envelope.AttestationV3Format, "tinfoil-go", "v0.15.7", "Go-http-client/2.0", http.StatusOK},
		{AttestationEndpointV3, envelope.AttestationV3Format, "tinfoil-go", "0.15.7", "python-requests/2.32.5", http.StatusOK},
		{AttestationEndpointV3, string(legacy.SevGuestV2), "tinfoil-go", "0.15.7", "", http.StatusBadRequest},
		{AttestationEndpointV3, string(legacy.SevGuestV2), "tinfoil-go", "0.15.7", "", http.StatusServiceUnavailable},
		{AttestationEndpointV3, envelope.AttestationV3Format, "tinfoil-go", "0.15.7", "", http.StatusFound},
		{AttestationEndpointV3, "", "tinfoil-go", "0.15.7", "", http.StatusOK},
	} {
		handler := m.observe(test.endpoint, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if test.format != "" {
				w.Header().Set(attestationFormatHeader, test.format)
			}
			w.WriteHeader(test.status)
			fmt.Fprint(w, "response")
		}))
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set(sdkNameHeader, test.sdk)
		request.Header.Set(sdkVersionHeader, test.version)
		request.Header.Set("User-Agent", test.userAgent)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, test.status, response.Code)
		require.Equal(t, "response", response.Body.String())
	}
	require.NoError(t, testutil.CollectAndCompare(m.requests, strings.NewReader(`
# HELP tfshim_attestation_requests_total Attestation HTTP requests by endpoint, served format, self-reported SDK, coarse User-Agent family, and response result; does not indicate client verification success.
# TYPE tfshim_attestation_requests_total counter
tfshim_attestation_requests_total{attestation_version="v2",client_family="go",endpoint="unversioned",result="served",sdk="unknown",sdk_version="unknown"} 1
tfshim_attestation_requests_total{attestation_version="v3",client_family="go",endpoint="unversioned",result="served",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="v3",client_family="python",endpoint="v3",result="served",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="none",client_family="unknown",endpoint="v3",result="client_error",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="none",client_family="unknown",endpoint="v3",result="server_error",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="none",client_family="unknown",endpoint="v3",result="other",sdk="tinfoil-go",sdk_version="0.15.7"} 1
tfshim_attestation_requests_total{attestation_version="none",client_family="unknown",endpoint="v3",result="served",sdk="tinfoil-go",sdk_version="0.15.7"} 1
`)))
}

func TestAttestationClientFamilies(t *testing.T) {
	for _, test := range []struct {
		userAgent, want string
	}{
		{"", "unknown"},
		{" \t ", "unknown"},
		{"Go-http-client/1.1", "go"},
		{"Go-http-client/2.0", "go"},
		{"python-requests/2.32.5", "python"},
		{"python-httpx/0.28.1", "python"},
		{"node", "node"},
		{"undici", "node"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36", "browser"},
		{"curl/8.10.1", "curl"},
		{"  curl/8.10.1\t", "curl"},
		{"custom-client/1.0 private-marker", "other"},
		{"custom-client/1.0 Go-http-client/1.1", "other"},
		{"Go-http-client-custom/1.1", "other"},
		{"node-custom", "other"},
	} {
		t.Run(test.userAgent, func(t *testing.T) {
			require.Equal(t, test.want, clientFamily(test.userAgent))
		})
	}
}

func TestAttestationClientFamiliesAggregateUserAgents(t *testing.T) {
	m := newAttestationMetrics()
	handler := m.observe(AttestationEndpointUnversioned, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(attestationFormatHeader, string(legacy.SevGuestV2))
		w.WriteHeader(http.StatusOK)
	}))
	for _, userAgent := range []string{
		"Go-http-client/1.1", "Go-http-client/2.0",
		"python-requests/2.32.5", "python-httpx/0.28.1",
		"custom-client/1.0 private-marker-a", "custom-client/2.0 private-marker-b",
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("User-Agent", userAgent)
		request.Header.Set(sdkVersionHeader, "9.8.7")
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	require.NoError(t, testutil.CollectAndCompare(m.requests, strings.NewReader(`
# HELP tfshim_attestation_requests_total Attestation HTTP requests by endpoint, served format, self-reported SDK, coarse User-Agent family, and response result; does not indicate client verification success.
# TYPE tfshim_attestation_requests_total counter
tfshim_attestation_requests_total{attestation_version="v2",client_family="go",endpoint="unversioned",result="served",sdk="unknown",sdk_version="unknown"} 2
tfshim_attestation_requests_total{attestation_version="v2",client_family="python",endpoint="unversioned",result="served",sdk="unknown",sdk_version="unknown"} 2
tfshim_attestation_requests_total{attestation_version="v2",client_family="other",endpoint="unversioned",result="served",sdk="unknown",sdk_version="unknown"} 2
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
		{"tinfoil-rs", "0.2.1", sdkIdentity{"tinfoil-rs", "0.2.1"}},
		{"tinfoil-swift", "0.8.2", sdkIdentity{"tinfoil-swift", "0.8.2"}},
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
	require.Equal(t, float64(2), testutil.ToFloat64(m.requests.WithLabelValues("v3", "v3", "tinfoil-go", "0.15.7", "unknown", "served")))
	require.Equal(t, float64(requestCount-maxSDKIdentities+1), testutil.ToFloat64(m.requests.WithLabelValues("v3", "v3", "tinfoil-go", "other", "unknown", "served")))
}
