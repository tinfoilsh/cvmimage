package main

import (
	"net/http"

	"tinfoil/internal/config"
	"tinfoil/internal/trustedtime"
)

func requireTrustedTime(config *config.Config, next http.Handler) http.Handler {
	return checkTrustedTime(config, next, trustedtime.Read)
}

func checkTrustedTime(config *config.Config, next http.Handler, read func() (trustedtime.Sample, error)) http.Handler {
	return corsMiddleware(config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			switch r.URL.EscapedPath() {
			case bootStagesPath, metricsPath, tinfoilMetricsPath, containersPath:
				next.ServeHTTP(w, r)
				return
			}
		}
		if _, err := read(); err != nil {
			writeAPIError(w, errTrustedTimeUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	}))
}
