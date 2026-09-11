package attestation

import "github.com/tinfoilsh/tinfoil-go/verifier/envelope"

// DeviceEvidenceProvider collects nonce-bound evidence for the configured devices.
type DeviceEvidenceProvider func([32]byte) ([]envelope.DeviceEvidenceItem, error)

func NoDeviceEvidence(_ [32]byte) ([]envelope.DeviceEvidenceItem, error) {
	return nil, nil
}
