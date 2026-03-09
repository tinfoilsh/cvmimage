package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireBearer(t *testing.T) {
	tests := []struct {
		name       string
		apiKey     string
		authHeader string
		wantOK     bool
		wantStatus int
	}{
		{"empty key allows all", "", "", true, 0},
		{"valid token", "secret", "Bearer secret", true, 0},
		{"case insensitive scheme", "secret", "bearer secret", true, 0},
		{"uppercase scheme", "secret", "BEARER secret", true, 0},
		{"wrong token", "secret", "Bearer wrong", false, http.StatusUnauthorized},
		{"missing header", "secret", "", false, http.StatusUnauthorized},
		{"no bearer prefix", "secret", "Basic secret", false, http.StatusUnauthorized},
		{"token only no scheme", "secret", "secret", false, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			ok := RequireBearer(tt.apiKey, w, r)
			if ok != tt.wantOK {
				t.Errorf("RequireBearer() = %v, want %v", ok, tt.wantOK)
			}
			if !ok && w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
