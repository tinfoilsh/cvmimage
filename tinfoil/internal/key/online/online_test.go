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

	httpmock.RegisterResponder("POST", "https://localhost:8080/validate",
		func(req *http.Request) (*http.Response, error) {
			apiKey, err := io.ReadAll(req.Body)
			if err != nil {
				return httpmock.NewStringResponse(http.StatusInternalServerError, "Internal server error"), nil
			}

			if string(apiKey) == "good-key" {
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

	err = v.Validate("bad-key")
	if assert.NotNil(t, err) {
		validationErr, ok := err.(*ValidationError)
		if assert.True(t, ok) {
			assert.Equal(t, http.StatusUnauthorized, validationErr.StatusCode)
			assert.NotContains(t, validationErr.Error(), "internal validator details")
		}
	}
}
