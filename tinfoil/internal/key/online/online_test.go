package online

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func allowLocalhost(t *testing.T) {
	t.Helper()
	saved := AllowedControlPlaneHosts
	AllowedControlPlaneHosts = append([]string{"localhost"}, saved...)
	t.Cleanup(func() { AllowedControlPlaneHosts = saved })
}

func keyHash(k string) string {
	h := sha256.Sum256([]byte(k))
	return hex.EncodeToString(h[:])
}

func TestVerifyOnline(t *testing.T) {
	allowLocalhost(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	goodHash := keyHash("good-key")

	httpmock.RegisterResponder("POST", "https://localhost:8080/validate",
		func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return httpmock.NewStringResponse(http.StatusInternalServerError, "Internal server error"), nil
			}

			if string(body) == goodHash {
				return httpmock.NewStringResponse(http.StatusOK, "OK"), nil
			}

			return httpmock.NewStringResponse(http.StatusUnauthorized, "Unauthorized"), nil
		})

	v, err := NewValidator("https://localhost:8080/validate")
	assert.Nil(t, err)

	assert.Nil(t, v.Validate("good-key"))
	assert.NotNil(t, v.Validate("bad-key"))
}

func TestRejectHTTP(t *testing.T) {
	allowLocalhost(t)
	_, err := NewValidator("http://localhost:8080/validate")
	assert.NotNil(t, err)
}

func TestRejectDisallowedHost(t *testing.T) {
	_, err := NewValidator("https://evil.example.com/validate")
	assert.NotNil(t, err)
}
