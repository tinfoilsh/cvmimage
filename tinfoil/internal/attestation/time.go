package attestation

import (
	"encoding/json"
	"fmt"
	"time"

	"encoding/json/jsontext"
	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"
)

const (
	AttestationV4Format = "https://tinfoil.sh/predicate/attestation/v4"
	GuestClockV1Format  = "https://tinfoil.sh/format/guest-clock/v1"
	GuestClockID        = "guest-clock"
	guestClockKind      = "guest-clock"
	guestClockVendor    = "tinfoil"
)

// GuestClockEvidence is a measured-software assertion at sampling time,
// not a hardware-supplied timestamp or a guarantee about other instants.
type GuestClockEvidence struct {
	UTC time.Time `json:"utc"`
}

// BuildTimedAttestation reads guest UTC after validating the challenge
// and binds the sample into the same quote as the nonce and channel keys.
// The v4 format requires a verifier that understands and appraises this claim.
func BuildTimedAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral wire.Response,
) (json.RawMessage, error) {
	return buildTimedAttestation(material, nonce, deviceEvidence, collateral, time.Now, reportWithRetry)
}

func buildTimedAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral wire.Response,
	readTime func() time.Time,
	readQuote quoteReader,
) (json.RawMessage, error) {
	if len(nonce) != envelope.NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", envelope.NonceSize, len(nonce))
	}
	utc := readTime().UTC()
	if utc.IsZero() {
		return nil, fmt.Errorf("guest clock sample is zero")
	}
	evidence, err := json.Marshal(GuestClockEvidence{UTC: utc})
	if err != nil {
		return nil, fmt.Errorf("encoding clock sample: %w", err)
	}

	items := make([]envelope.DeviceEvidenceItem, len(deviceEvidence), len(deviceEvidence)+1)
	copy(items, deviceEvidence)
	items = append(items, envelope.DeviceEvidenceItem{
		ID:       GuestClockID,
		Kind:     guestClockKind,
		Vendor:   guestClockVendor,
		Format:   GuestClockV1Format,
		Evidence: jsontext.Value(evidence),
	})
	doc, err := buildAttestation(material, nonce, items, collateral, readQuote)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(doc, &fields); err != nil {
		return nil, fmt.Errorf("decoding attestation: %w", err)
	}
	fields["format"], err = json.Marshal(AttestationV4Format)
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}
