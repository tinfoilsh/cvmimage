package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"tinfoil/internal/config"
)

func TestMetricsHandlersRejectMissingAuthenticationConfig(t *testing.T) {
	externalConfig := &config.ExternalConfig{}
	tests := []struct {
		name    string
		path    string
		handler http.Handler
	}{
		{
			name:    "JSON metrics",
			path:    "/.well-known/tinfoil-metrics",
			handler: HandleMetrics(externalConfig),
		},
		{
			name:    "Prometheus metrics",
			path:    "/.well-known/metrics",
			handler: HandlePrometheusMetrics(&externalConfig.Metadata, ""),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			rec := httptest.NewRecorder()

			test.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}
