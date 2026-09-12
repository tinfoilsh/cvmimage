package shim

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"tinfoil/internal/volume"
)

var volumeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// volumeHandler exposes only status and operator unlock. Sandbox enrollment
// must pass through its SSH-key validation and cannot use this route.
func volumeHandler(client volume.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == volume.ManagementPath {
			state, err := client.Status(r.Context())
			if err != nil {
				http.Error(w, "storage starting", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(state)
			return
		}
		name, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, volume.ManagementPath+"/"), "/unlock")
		if !strings.HasPrefix(r.URL.Path, volume.ManagementPath+"/") || !ok || r.Method != "POST" || !volumeNamePattern.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Key []byte `json:"key,omitempty"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid key", 400)
			return
		}
		defer clear(body.Key)
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid request", 400)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			http.Error(w, "permit required", 401)
			return
		}
		if err := client.Unlock(r.Context(), name, volume.Request{Key: body.Key, Permit: token}); err != nil {
			http.Error(w, "volume activation refused", 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
