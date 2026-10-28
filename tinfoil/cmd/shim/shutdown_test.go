package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShutdownHandler(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		method    string
		auth      string
		signalErr error
		want      int
		signalled bool
	}{
		{"accepts the host token", "secret", http.MethodPost, "Bearer secret", nil, http.StatusAccepted, true},
		{"rejects a wrong token", "secret", http.MethodPost, "Bearer guess", nil, http.StatusUnauthorized, false},
		{"rejects a missing token", "secret", http.MethodPost, "", nil, http.StatusUnauthorized, false},
		{"rejects GET", "secret", http.MethodGet, "Bearer secret", nil, http.StatusMethodNotAllowed, false},
		{"disabled without a configured token", "", http.MethodPost, "Bearer ", nil, http.StatusNotFound, false},
		{"reports a failed signal", "secret", http.MethodPost, "Bearer secret", errors.New("denied"), http.StatusInternalServerError, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signalled := false
			handler := shutdownHandler(tt.token, func() error {
				signalled = true
				return tt.signalErr
			})
			req := httptest.NewRequest(tt.method, shutdownPath, nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if signalled != tt.signalled {
				t.Fatalf("signalled = %v, want %v", signalled, tt.signalled)
			}
		})
	}
}
