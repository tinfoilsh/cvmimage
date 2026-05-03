package online

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

	"tinfoil/internal/key"
)

func TestVerifyOnline(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	var lastModel string
	responder := func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return httpmock.NewStringResponse(http.StatusInternalServerError, "Internal server error"), nil
		}

		var parsed key.Request
		if err := json.Unmarshal(body, &parsed); err != nil {
			return httpmock.NewStringResponse(http.StatusBadRequest, "bad json"), nil
		}
		lastModel = parsed.Model

		if parsed.APIKey == "good-key" {
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

	assert.Nil(t, v.Validate(key.Request{APIKey: "good-key", Model: "llama-3"}))
	assert.Equal(t, "llama-3", lastModel)

	assert.NotNil(t, v.Validate(key.Request{APIKey: "bad-key"}))

	assert.Nil(t, v.ValidateWithIP(key.Request{APIKey: "good-key", Model: "mixtral"}))
	assert.Equal(t, "mixtral", lastModel)

	assert.NotNil(t, v.ValidateWithIP(key.Request{APIKey: "bad-key"}))
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
