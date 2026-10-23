package attestationmaterial

import (
	"bytes"
	"encoding/json"
	"fmt"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
)

const RequestVersionDocument = 2

type Request struct {
	Version  int             `json:"version"`
	Repo     string          `json:"repo,omitempty"`
	Tag      string          `json:"tag,omitempty"`
	Profile  string          `json:"profile"`
	Digest   string          `json:"digest,omitempty"`
	Config   []byte          `json:"config_base64,omitempty"`
	Document json.RawMessage `json:"document"`
}

func (r Request) Validate() error {
	if r.Version != RequestVersionDocument {
		return fmt.Errorf("unsupported collateral request version %d", r.Version)
	}
	if len(r.Document) == 0 || bytes.Equal(bytes.TrimSpace(r.Document), []byte("null")) {
		return fmt.Errorf("collateral request requires an attestation document")
	}
	if r.Profile != wire.FormatV3 {
		return fmt.Errorf("unsupported collateral request profile %q", r.Profile)
	}
	if len(r.Config) != 0 {
		if r.Repo != "" || r.Tag != "" || r.Digest != "" {
			return fmt.Errorf("local config and registry references are mutually exclusive")
		}
	} else if r.Repo == "" || r.Tag == "" || r.Digest == "" {
		return fmt.Errorf("registry collateral request requires a project, revision, and config digest")
	}
	return nil
}
