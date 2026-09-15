package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"tinfoil/internal/boot"
)

func TestStatusOnlyShimServesTerminalFailureWithoutBootArtifacts(t *testing.T) {
	// The host missed every intermediate poll; only the final snapshot remains.
	state := &boot.State{
		StartedAt: time.Now().Add(-time.Minute).UTC(), CompletedAt: time.Now().UTC(),
		Stages: []boot.Stage{
			{Name: boot.StageCertificate, Status: boot.StatusOK},
			{Name: boot.StageModels, Status: boot.StatusFailed, Detail: "dm-verity corruption"},
			{Name: boot.StageShim, Status: boot.StatusSkipped, Detail: "not run because boot failed"},
		},
	}
	srv, err := newShimServer(true, func() (*boot.State, error) { return state, nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(srv.Handler)
	server.TLS = srv.TLSConfig
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	// Host boot-status polling accepts the bootstrap self-signed certificate.
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	for _, path := range []string{"/", "/v1/chat/completions", "/.well-known/tinfoil-boot-stages"} {
		resp, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if path != "/.well-known/tinfoil-boot-stages" {
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("%s returned %d, want 503", path, resp.StatusCode)
			}
			continue
		}
		var got boot.State
		err = json.NewDecoder(resp.Body).Decode(&got)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil || !reflect.DeepEqual(&got, state) {
			t.Fatalf("status response = %d, %+v, %v", resp.StatusCode, got, err)
		}
	}
}

func TestBootStatusUnavailableDoesNotReportSuccess(t *testing.T) {
	handler := bootStagesHandler(func() (*boot.State, error) { return nil, os.ErrNotExist })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-boot-stages", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing state returned %d, want 503", response.Code)
	}
}
