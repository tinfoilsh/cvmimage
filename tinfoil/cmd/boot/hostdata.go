package main

import (
	"encoding/hex"
	"fmt"

	"tinfoil/internal/attestation"
)

// HOST_DATA: 32 bytes the host commits to at launch, at offset 0xC0 of an
// SEV-SNP report. It is outside the launch digest, so the config it names can
// change without changing the measurement.
const (
	hostDataOffset = 0xC0
	hostDataSize   = 32
)

// measuredConfigHash reads the config hash the host committed to at launch.
// The report exists only to carry HOST_DATA, so it binds no key.
func measuredConfigHash() (string, error) {
	report, platform, err := attestation.Report([64]byte{})
	if err != nil {
		return "", fmt.Errorf("reading launch config hash: %w", err)
	}
	if platform != attestation.PlatformSEVSNP {
		return "", fmt.Errorf("launch config hash needs SEV-SNP, got %s", platform)
	}
	if len(report) < hostDataOffset+hostDataSize {
		return "", fmt.Errorf("attestation report is %d bytes, short of HOST_DATA", len(report))
	}
	return hex.EncodeToString(report[hostDataOffset : hostDataOffset+hostDataSize]), nil
}
