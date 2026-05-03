package online

import (
	"io"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestVerifyOnline(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	responder := func(req *http.Request) (*http.Response, error) {
		apiKey, err := io.ReadAll(req.Body)
		if err != nil {
			return httpmock.NewStringResponse(http.StatusInternalServerError, "Internal server error"), nil
		}

		if string(apiKey) == "good-key" {
			return httpmock.NewStringResponse(http.StatusOK, "OK"), nil
		}

		return httpmock.NewStringResponse(http.StatusUnauthorized, "Unauthorized"), nil
	}
	httpmock.RegisterResponder("POST", "https://localhost:8080/validate-key", responder)
	httpmock.RegisterResponder("POST", "https://localhost:8080/validate-key-and-ip", responder)

	v, err := NewValidator(
		"https://localhost:8080/validate-key",
		"https://localhost:8080/validate-key-and-ip",
	)
	assert.Nil(t, err)

	assert.Nil(t, v.Validate("good-key"))
	assert.NotNil(t, v.Validate("bad-key"))
	assert.Nil(t, v.ValidateWithIP("good-key"))
	assert.NotNil(t, v.ValidateWithIP("bad-key"))
}

func TestRejectHTTP(t *testing.T) {
	_, err := NewValidator(
		"http://localhost:8080/validate-key",
		"https://localhost:8080/validate-key-and-ip",
	)
	assert.NotNil(t, err)

	_, err = NewValidator(
		"https://localhost:8080/validate-key",
		"http://localhost:8080/validate-key-and-ip",
	)
	assert.NotNil(t, err)
}
