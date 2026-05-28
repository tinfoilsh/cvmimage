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

	var lastReq key.Request
	httpmock.RegisterResponder("POST", "https://localhost:8080/validate",
		func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return httpmock.NewStringResponse(http.StatusInternalServerError, "Internal server error"), nil
			}

			var parsed key.Request
			if err := json.Unmarshal(body, &parsed); err != nil {
				return httpmock.NewStringResponse(http.StatusBadRequest, "bad json"), nil
			}
			lastReq = parsed

			if parsed.APIKey == "good-key" {
				return httpmock.NewStringResponse(http.StatusOK, "OK"), nil
			}

			return httpmock.NewStringResponse(http.StatusUnauthorized, "Unauthorized"), nil
		})

	v, err := NewValidator("https://localhost:8080/validate")
	assert.Nil(t, err)

	assert.Nil(t, v.Validate(key.Request{
		APIKey:        "good-key",
		Domain:        "model.example.com",
		RequestedHost: "realtime-model.model.example.com",
		Path:          "/v1/chat/completions",
	}))
	assert.Equal(t, "model.example.com", lastReq.Domain)
	assert.Equal(t, "realtime-model.model.example.com", lastReq.RequestedHost)
	assert.Equal(t, "/v1/chat/completions", lastReq.Path)

	assert.NotNil(t, v.Validate(key.Request{APIKey: "bad-key"}))
}

func TestRejectHTTP(t *testing.T) {
	_, err := NewValidator("http://localhost:8080/validate")
	assert.NotNil(t, err)
}

func TestValidationErrorCarriesOnlyStatus(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://localhost:8080/validate",
		httpmock.NewStringResponder(http.StatusUnauthorized, "internal validator details"))

	v, err := NewValidator("https://localhost:8080/validate")
	assert.Nil(t, err)

	err = v.Validate(key.Request{APIKey: "bad-key"})
	if assert.NotNil(t, err) {
		validationErr, ok := err.(*ValidationError)
		if assert.True(t, ok) {
			assert.Equal(t, http.StatusUnauthorized, validationErr.StatusCode)
			assert.NotContains(t, validationErr.Error(), "internal validator details")
		}
	}
}
