package attestation

import (
	"fmt"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

// DeviceEvidenceProvider collects nonce-bound evidence for the configured devices.
type DeviceEvidenceProvider func([32]byte, int) ([]envelope.DeviceEvidenceItem, error)

func NoDeviceEvidence(_ [32]byte, expected int) ([]envelope.DeviceEvidenceItem, error) {
	if expected != 0 {
		return nil, fmt.Errorf("device evidence is unavailable for %d configured devices", expected)
	}
	return nil, nil
}
