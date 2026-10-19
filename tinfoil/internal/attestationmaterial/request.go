package attestationmaterial

import (
	"encoding/json"
	"fmt"
)

const (
	RequestVersionLegacy   = 1
	RequestVersionDocument = 2
)

// Request versions ATC service plumbing independently of the attestation and
// collateral formats. Document carries no collateral or private key material.
type Request struct {
	Version     int             `json:"version,omitempty"`
	Repo        string          `json:"repo,omitempty"`
	Tag         string          `json:"tag,omitempty"`
	Document    json.RawMessage `json:"document,omitempty"`
	Platform    string          `json:"platform,omitempty"`
	QuoteBase64 string          `json:"quote_base64,omitempty"`
}

func (r Request) Validate() error {
	switch r.Version {
	case 0, RequestVersionLegacy:
		if len(r.Document) != 0 || r.Platform == "" || r.QuoteBase64 == "" {
			return fmt.Errorf("legacy collateral request requires platform and quote_base64 without a document")
		}
	case RequestVersionDocument:
		if len(r.Document) == 0 || string(r.Document) == "null" || r.Platform != "" || r.QuoteBase64 != "" {
			return fmt.Errorf("document collateral request requires a document without platform or quote_base64")
		}
	default:
		return fmt.Errorf("unsupported collateral request version %d", r.Version)
	}
	return nil
}
