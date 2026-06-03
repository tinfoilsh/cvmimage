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

// Result is the non-secret outcome of a successful validation. It lets the shim
// forward the authenticated principal to the upstream workload so the workload
// can attribute usage and rate limits to a stable identity instead of the
// (rotating) bearer credential.
type Result struct {
	// Subject is the authenticated principal — the JWT `sub` — when the
	// credential is a locally-verified JWT access token. It is empty for opaque
	// API keys, whose subject is known only to the control plane.
	Subject string
}

type Validator interface {
	Validate(req Request) (Result, error)
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

func (c *Chain) Validate(req Request) (Result, error) {
	var res Result
	var err error
	for _, v := range c.validators {
		res, err = v.Validate(req)
		if !errors.Is(err, ErrUnsupportedToken) {
			return res, err
		}
	}
	return res, err
}
