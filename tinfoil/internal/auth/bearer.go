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
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token != apiKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
