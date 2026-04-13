package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// RequireBearer returns 401 if the request doesn't carry the expected token.
// An empty apiKey is treated as "not configured" and rejects all requests.
func RequireBearer(apiKey string, w http.ResponseWriter, r *http.Request) bool {
	if apiKey == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	header := r.Header.Get("Authorization")
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	token := header[7:]
	if subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
