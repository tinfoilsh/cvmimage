package main

import (
	"net/http"

	"tinfoil/internal/trustedtime"
)

func requireTrustedTime(next http.Handler) http.Handler {
	return checkTrustedTime(next, trustedtime.Read)
}

func checkTrustedTime(next http.Handler, read func() (trustedtime.Sample, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := read(); err != nil {
			http.Error(w, "authenticated time unavailable", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}
