package main

import (
	"net/http"
	"os"

	"tinfoil/internal/boot"
)

func containersHandler() http.HandlerFunc {
	return serveContainerStatusFile(boot.ContainerStatusPath)
}

func serveContainerStatusFile(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "container status not available", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}
