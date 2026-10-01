package attestation

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	"tinfoil/internal/trustedtime"
)

const (
	AttestationV4Format = "https://tinfoil.sh/predicate/attestation/v4"
	GuestClockV1Format  = "https://tinfoil.sh/format/guest-clock/v1"
	GuestClockID        = "guest-clock"
	guestClockKind      = "guest-clock"
	guestClockVendor    = "tinfoil"
	clockSynchronized   = "synchronized"
)

var ErrClockUnavailable = errors.New("trusted guest clock unavailable")

// GuestClockEvidence is a measured-software assertion at sampling time,
// not a hardware-supplied timestamp or a guarantee about other instants.
type GuestClockEvidence struct {
	UTC                    time.Time `json:"utc"`
	Status                 string    `json:"status"`
	UncertaintyNanoseconds int64     `json:"uncertainty_ns"`
}

// BuildTimedAttestation reads the trusted clock after validating the challenge
// and binds the sample into the same quote as the nonce and channel keys.
// The v4 format requires a verifier that understands and appraises this claim.
func BuildTimedAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral []envelope.CollateralEntry,
	readTime func() (trustedtime.Sample, error),
) (*envelope.Document, error) {
	return buildTimedAttestation(material, nonce, deviceEvidence, collateral, readTime, reportWithRetry)
}

func buildTimedAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral []envelope.CollateralEntry,
	readTime func() (trustedtime.Sample, error),
	readQuote quoteReader,
) (*envelope.Document, error) {
	if len(nonce) != envelope.NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", envelope.NonceSize, len(nonce))
	}
	if readTime == nil {
		return nil, ErrClockUnavailable
	}
	sample, err := readTime()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClockUnavailable, err)
	}
	if sample.Time.IsZero() || sample.Uncertainty < 0 || sample.Uncertainty > trustedtime.MaxUncertainty {
		return nil, fmt.Errorf("%w: invalid clock sample", ErrClockUnavailable)
	}
	evidence, err := json.Marshal(GuestClockEvidence{
		UTC:                    sample.Time.UTC(),
		Status:                 clockSynchronized,
		UncertaintyNanoseconds: int64(sample.Uncertainty),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encoding clock sample: %v", ErrClockUnavailable, err)
	}
	items := make([]envelope.DeviceEvidenceItem, len(deviceEvidence), len(deviceEvidence)+1)
	copy(items, deviceEvidence)
	items = append(items, envelope.DeviceEvidenceItem{
		ID:       GuestClockID,
		Kind:     guestClockKind,
		Vendor:   guestClockVendor,
		Format:   GuestClockV1Format,
		Evidence: evidence,
	})
	doc, err := buildAttestation(material, nonce, items, collateral, readQuote)
	if err != nil {
		return nil, err
	}
	doc.Format = AttestationV4Format
	return doc, nil
}
