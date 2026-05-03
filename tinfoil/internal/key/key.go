package key

// Request is the payload sent to the control plane for API key validation.
// The Model field is optional and used for per-key/per-org policy checks
// (e.g. model blocklists) on the control plane side.
type Request struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model,omitempty"`
}

type Validator interface {
	Validate(req Request) error
	ValidateWithIP(req Request) error
}
