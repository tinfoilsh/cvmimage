package key

// Request is the payload sent to the control plane for API key validation.
// Model and Path are optional policy inputs for the control plane.
type Request struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model,omitempty"`
	Path   string `json:"path,omitempty"`
}

type Validator interface {
	Validate(req Request) error
}
