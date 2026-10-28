package main

import (
	"log"
	"net/http"
	"syscall"

	"tinfoil/internal/auth"
)

const shutdownPath = "/.well-known/tinfoil-shutdown"

// shutdownHandler lets the host start the same shutdown SIGTERM does: pid1
// drains this shim, stops the workload, and resets the guest so QEMU exits.
// The token comes from the unmeasured external config. It keeps clients and
// other tenants out; the host that holds it could kill the VM anyway.
func shutdownHandler(token string, signalInit func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Keep the path out of the workload proxy even when disabled.
		if token == "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !auth.RequireBearer(token, w, r) {
			return
		}
		if err := signalInit(); err != nil {
			log.Printf("Host shutdown request: signalling pid1: %v", err)
			http.Error(w, "shutdown failed", http.StatusInternalServerError)
			return
		}
		log.Print("Host requested shutdown")
		w.WriteHeader(http.StatusAccepted)
	}
}

func signalInit() error {
	return syscall.Kill(1, syscall.SIGTERM)
}
