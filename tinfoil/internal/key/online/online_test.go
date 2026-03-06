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

	httpmock.RegisterResponder("POST", "http://localhost:8080/validate",
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

	v, err := NewValidator("http://localhost:8080/validate")
	assert.Nil(t, err)

	assert.Nil(t, v.Validate("good-key"))
	assert.NotNil(t, v.Validate("bad-key"))
}
