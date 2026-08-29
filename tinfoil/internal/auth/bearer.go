package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func writeUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// RequireBearer returns 401 if the request doesn't carry the expected token.
// If apiKey is empty, all requests are allowed.
func RequireBearer(apiKey string, w http.ResponseWriter, r *http.Request) bool {
	if apiKey == "" {
		return true
	}
	header := r.Header.Get("Authorization")
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		writeUnauthorized(w)
		return false
	}
	token := header[7:]
	if subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
		writeUnauthorized(w)
		return false
	}
	return true
}

// RequireConfiguredBearer returns 401 unless a non-empty expected token is configured and supplied.
func RequireConfiguredBearer(apiKey string, w http.ResponseWriter, r *http.Request) bool {
	if apiKey == "" {
		writeUnauthorized(w)
		return false
	}
	return RequireBearer(apiKey, w, r)
}
