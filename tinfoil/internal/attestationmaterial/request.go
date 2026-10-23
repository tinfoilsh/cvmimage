package attestationmaterial

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const RequestVersionDocument = 2

// Request versions ATC service plumbing independently of the attestation and
// collateral formats. Document carries no collateral or private key material.
type Request struct {
	Version  int             `json:"version"`
	Repo     string          `json:"repo"`
	Tag      string          `json:"tag,omitempty"`
	Document json.RawMessage `json:"document"`
}

func (r Request) Validate() error {
	if r.Version != RequestVersionDocument {
		return fmt.Errorf("unsupported collateral request version %d", r.Version)
	}
	if len(r.Document) == 0 || bytes.Equal(bytes.TrimSpace(r.Document), []byte("null")) {
		return fmt.Errorf("collateral request requires a document")
	}
	if r.Repo == "" {
		return fmt.Errorf("collateral request requires a repository")
	}
	return nil
}
