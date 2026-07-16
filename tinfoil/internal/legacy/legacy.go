// Package legacy carries the v2 attestation wire format. SDKs dropped v2
// verification; producers keep serving it until legacy SDK usage is
// retired, so the wire types now live here.
package legacy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

// PredicateType identifies a v2 document format.
type PredicateType string

const (
	SevGuestV2 PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	TdxGuestV2 PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v2"
	DummyV2    PredicateType = "https://tinfoil.sh/predicate/dummy/v2"
)

// Document is the v2 attestation document.
type Document struct {
	Format PredicateType `json:"format"`
	Body   string        `json:"body"`
}

// Hash returns the SHA-256 hash of the document (v2 dcode SAN encoding).
func (d *Document) Hash() string {
	all := string(d.Format) + d.Body
	return fmt.Sprintf("%x", sha256.Sum256([]byte(all)))
}

// Bundle is the v2 single-request attestation bundle.
type Bundle struct {
	Domain                   string          `json:"domain"`
	EnclaveAttestationReport *Document       `json:"enclaveAttestationReport"`
	Digest                   string          `json:"digest"`
	SigstoreBundle           json.RawMessage `json:"sigstoreBundle"`
	VCEK                     string          `json:"vcek"`
	EnclaveCert              string          `json:"enclaveCert"`
}

// FromFile loads a v2 document from disk.
func FromFile(path string) (*Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var doc Document
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
