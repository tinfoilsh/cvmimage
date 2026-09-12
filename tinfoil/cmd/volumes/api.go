package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"tinfoil/internal/volume"
)

type volumeManager interface {
	Definition(string) (volume.Definition, bool)
	Snapshot() volume.Snapshot
	Activate(context.Context, string, []byte, []byte) error
}

func handler(m volumeManager, domain string, verify func(string, string, string, string) error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.Snapshot())
	})
	activate := func(enrollment bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			d, ok := m.Definition(name)
			if !ok {
				http.NotFound(w, r)
				return
			}
			u := d.Unlock
			if enrollment {
				if u.Runtime != "owner" {
					http.Error(w, "enrollment unavailable", 403)
					return
				}
			} else if u.Runtime != "operator" && u.Secret == "" {
				http.Error(w, "unlock unavailable", 403)
				return
			}
			var request volume.Request
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			defer clear(request.Key)
			defer clear(request.Binding)
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				http.Error(w, "invalid request", 400)
				return
			}
			scope := name
			if enrollment {
				scope = ""
			} else if len(request.Binding) != 0 {
				http.Error(w, "owner binding unavailable", 400)
				return
			}
			if err := verify(request.Permit, domain, m.Snapshot().Nonce, scope); err != nil {
				http.Error(w, "permit refused", 403)
				return
			}
			if err := m.Activate(r.Context(), name, request.Key, request.Binding); err != nil {
				http.Error(w, "volume activation refused", 409)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}
	mux.HandleFunc("POST /v1/unlock/{name}", activate(false))
	mux.HandleFunc("POST /v1/enroll/{name}", activate(true))
	return mux
}
