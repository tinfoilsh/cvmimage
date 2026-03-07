package auth

import (
	"net/http"
	"strings"
)

// RequireBearer returns 401 if the request doesn't carry the expected token.
// If apiKey is empty, all requests are allowed.
func RequireBearer(apiKey string, w http.ResponseWriter, r *http.Request) bool {
	if apiKey == "" {
		return true
	}
	header := r.Header.Get("Authorization")
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	token := header[7:]
	if token != apiKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
