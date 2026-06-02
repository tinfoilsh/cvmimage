package key

import (
	"errors"
	"net/http"
)

// Request is the payload sent to the control plane for API key validation.
// Domain, RequestedHost, and Path are optional policy inputs for the control plane.
type Request struct {
	APIKey        string `json:"api_key"`
	Domain        string `json:"domain,omitempty"`
	RequestedHost string `json:"requested_host,omitempty"`
	Path          string `json:"path,omitempty"`
}

type Validator interface {
	Validate(req Request) error
}

// ErrUnsupportedToken signals that a Validator cannot handle the presented
// credential's format, so a Chain should advance to the next validator.
var ErrUnsupportedToken = errors.New("unsupported token format")

// ValidationError is returned when a credential is rejected. It carries only an
// HTTP status code so internal validator details never leak to callers.
type ValidationError struct {
	StatusCode int
}

func (e *ValidationError) Error() string {
	return http.StatusText(e.StatusCode)
}

// Chain tries validators in order, advancing to the next only when one reports
// ErrUnsupportedToken. The first definitive result (a success or a
// ValidationError) is returned to the caller.
type Chain struct {
	validators []Validator
}

// NewChain returns a Validator that consults each validator in turn.
func NewChain(validators ...Validator) *Chain {
	return &Chain{validators: validators}
}

func (c *Chain) Validate(req Request) error {
	var err error
	for _, v := range c.validators {
		err = v.Validate(req)
		if !errors.Is(err, ErrUnsupportedToken) {
			return err
		}
	}
	return err
}
