package shim

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"tinfoil/internal/volume"
)

func TestVolumeHandlerForwardsStatusAndOperatorUnlock(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "volumes.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	type forwarded struct {
		path    string
		request volume.Request
	}
	requests := make(chan forwarded, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request volume.Request
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
		}
		requests <- forwarded{r.URL.Path, request}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(volume.Snapshot{Initialized: true, Nonce: "boot-nonce"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	handler := volumeHandler(volume.Client{Socket: socket})
	for _, tt := range []struct {
		name, method, suffix, body, authorization string
		want                                      int
		forward                                   string
	}{
		{"status", "GET", "", "", "", 200, "/v1/status"},
		{"unlock", "POST", "/state/unlock", `{"key":"AQI="}`, "Bearer permit", 204, "/v1/unlock/state"},
		{"secret unlock", "POST", "/state/unlock", `{}`, "Bearer permit", 204, "/v1/unlock/state"},
		{"enrollment is private", "POST", "/state/enroll", `{}`, "Bearer permit", 404, ""},
		{"owner binding is private", "POST", "/state/unlock", `{"binding":"owner"}`, "Bearer permit", 400, ""},
		{"missing permit", "POST", "/state/unlock", `{}`, "", 401, ""},
		{"trailing JSON", "POST", "/state/unlock", `{} {}`, "Bearer permit", 400, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, volume.ManagementPath+tt.suffix, strings.NewReader(tt.body))
			request.Header.Set("Authorization", tt.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tt.want {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			select {
			case got := <-requests:
				if tt.forward == "" || got.path != tt.forward {
					t.Fatalf("unexpected forwarding to %s", got.path)
				}
				if tt.method == "POST" && (got.request.Permit != "permit" || len(got.request.Binding) != 0) {
					t.Fatal("incorrect unlock authority")
				}
				if tt.name == "unlock" && string(got.request.Key) != "\x01\x02" {
					t.Fatal("unlock key changed")
				}
			default:
				if tt.forward != "" {
					t.Fatal("request was not forwarded")
				}
			}
			if tt.name == "status" {
				var state volume.Snapshot
				if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil || !state.Initialized || state.Nonce != "boot-nonce" {
					t.Fatalf("status forwarding: %+v, %v", state, err)
				}
			}
		})
	}
}
