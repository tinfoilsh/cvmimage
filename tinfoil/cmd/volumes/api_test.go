package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	config "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/volume"
)

func TestUnlockAPIRoutesAndAuthority(t *testing.T) {
	owner := volume.Definition{Name: "workspace", Unlock: config.VolumeUnlock{Runtime: "owner"}}
	operator := volume.Definition{Name: "state", Unlock: config.VolumeUnlock{Runtime: "operator"}}
	for _, tt := range []struct {
		path, token string
		binding     bool
		want        int
	}{
		{"/v1/unlock/workspace", "permit", false, 403},
		{"/v1/enroll/state", "permit", true, 403},
		{"/v1/unlock/state", "invalid", false, 403},
		{"/v1/unlock/state", "permit", true, 400},
		{"/v1/unlock/state", "permit", false, 204},
		{"/v1/enroll/workspace", "permit", true, 204},
	} {
		t.Run(tt.path+tt.token, func(t *testing.T) {
			m, err := volume.NewManager(volume.Plan{Volumes: []volume.Definition{owner, operator}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := m.Close(); err != nil {
					t.Error(err)
				}
			})
			verified := false
			manager := &fakeManager{Manager: m}
			handler := handler(manager, "guest.example", func(token, domain, nonce, scope string) error {
				if token != "permit" {
					return errors.New("bad permit")
				}
				if domain != "guest.example" || nonce != m.Snapshot().Nonce {
					t.Fatal("incorrect authority")
				}
				if tt.path == "/v1/unlock/state" && scope != "state" {
					t.Fatal("missing volume scope")
				}
				if tt.path == "/v1/enroll/workspace" && scope != "" {
					t.Fatal("legacy enrollment scope changed")
				}
				verified = true
				return nil
			})
			request := volume.Request{Key: make([]byte, 64), Permit: tt.token}
			if tt.binding {
				request.Binding = []byte("owner")
			}
			data, _ := json.Marshal(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(data)))
			if response.Code != tt.want {
				t.Fatalf("%d: %s", response.Code, response.Body.String())
			}
			if response.Code == 204 && !verified {
				t.Fatal("activation did not verify authority")
			}
			if manager.called != (response.Code == 204) {
				t.Fatal("unexpected activation call")
			}
			if manager.called && (manager.name != path.Base(tt.path) || !bytes.Equal(manager.key, request.Key) || !bytes.Equal(manager.binding, request.Binding)) {
				t.Fatal("activation did not receive the requested volume, key, and binding")
			}
		})
	}
}

type fakeManager struct {
	*volume.Manager
	called       bool
	name         string
	key, binding []byte
}

func (m *fakeManager) Activate(_ context.Context, name string, key, binding []byte) error {
	m.called = true
	m.name = name
	m.key = bytes.Clone(key)
	m.binding = bytes.Clone(binding)
	return nil
}
