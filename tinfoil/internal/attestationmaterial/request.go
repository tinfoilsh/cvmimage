package attestationmaterial

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

const RequestVersionDocument = 2

type Request struct {
	Version  int             `json:"version"`
	Repo     string          `json:"repo,omitempty"`
	Tag      string          `json:"tag,omitempty"`
	Profile  string          `json:"profile"`
	Digest   string          `json:"digest,omitempty"`
	Runtime  string          `json:"runtime,omitempty"`
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
		if r.Repo != "" || r.Tag != "" || r.Digest != "" || r.Runtime != "" {
			return fmt.Errorf("local config and registry references are mutually exclusive")
		}
	} else if r.Runtime != "" {
		digest, err := hex.DecodeString(r.Digest)
		if r.Repo != "" || r.Tag != "" || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != r.Digest {
			return fmt.Errorf("local runtime reference requires a config digest and excludes registry references")
		}
		tag, digestHex, _ := strings.Cut(r.Runtime, "@sha256:")
		runtime := configendorsement.RuntimeReference{Repo: configendorsement.RuntimeRepo, Tag: tag, Digest: digestHex}
		if err := runtime.Validate(); err != nil {
			return err
		}
	} else if r.Repo == "" || r.Tag == "" || r.Digest == "" {
		return fmt.Errorf("registry collateral request requires a project, revision, and config digest")
	}
	return nil
}
