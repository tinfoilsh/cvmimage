// Package keyreq holds the wire-level request payload for the shim's
// API key validation calls to the control plane. It exists in its own
// package to avoid an import cycle between the key interface package
// and the online/offline validator implementations.
package keyreq

// Request is the payload sent to the control plane for API key validation.
// The Model field is optional and used for per-key/per-org policy checks
// (e.g. model blocklists) on the control plane side.
type Request struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model,omitempty"`
}
