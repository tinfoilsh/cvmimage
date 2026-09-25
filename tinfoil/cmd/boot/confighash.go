package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxclient "github.com/google/go-tdx-guest/client"
	tdxlabi "github.com/google/go-tdx-guest/client/linuxabi"

	"tinfoil/internal/attestation"
)

// HOST_DATA: 32 bytes the host commits to at launch, at offset 0xC0 of an
// SEV-SNP report. It is outside the launch digest, so the config it names can
// change without changing the measurement.
const (
	hostDataOffset = 0xC0
	hostDataSize   = 32
)

// MRCONFIGID is TDX's equivalent, 48 bytes, so it carries the 32-byte config
// hash followed by 16 zero bytes. TDINFO_STRUCT starts halfway through
// TDREPORT_STRUCT, after REPORTMACSTRUCT and TEE_TCB_INFO, and ATTRIBUTES,
// XFAM and MRTD precede MRCONFIGID within it.
const (
	reportMACStructSize = 256 // REPORTMACSTRUCT
	teeTCBInfoSize      = 256 // TEE_TCB_INFO and the reserved bytes after it
	tdInfoOffset        = reportMACStructSize + teeTCBInfoSize
	mrConfigIDOffset    = tdInfoOffset + tdxabi.TdAttributesSize + tdxabi.XfamSize + tdxabi.MrTdSize
)

// measuredConfigHash reads the config hash the host committed to at launch.
// It binds no key, so it needs only the platform's own launch-time fields.
func measuredConfigHash() (string, error) {
	platform, err := attestation.DevicePlatform()
	if err != nil {
		return "", fmt.Errorf("reading launch config hash: %w", err)
	}
	switch platform {
	case attestation.PlatformSEVSNP:
		return hostDataConfigHash()
	case attestation.PlatformTDX:
		return mrConfigIDConfigHash()
	}
	return "", fmt.Errorf("launch config hash needs SEV-SNP or TDX, got %s", platform)
}

// hostDataConfigHash takes the hash from HOST_DATA in an SEV-SNP report.
func hostDataConfigHash() (string, error) {
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

// mrConfigIDConfigHash takes the hash from MRCONFIGID in a TD report. The
// report is the local one the TDX module writes on request, not a quote: the
// config stage runs before attestation, and reading the guest's own registers
// must not depend on the host's quote generation service.
func mrConfigIDConfigHash() (string, error) {
	device, err := tdxclient.OpenDevice()
	if err != nil {
		return "", fmt.Errorf("opening TDX guest device: %w", err)
	}
	defer device.Close()

	request := tdxlabi.TdxReportReq{}
	result, err := device.Ioctl(tdxlabi.IocTdxGetReport, &request)
	if err != nil {
		return "", fmt.Errorf("reading TD report: %w", err)
	}
	if result != uintptr(tdxlabi.TdxAttestSuccess) {
		return "", fmt.Errorf("reading TD report: status %d", result)
	}
	return configHashFromMRCONFIGID(request.TdReport[mrConfigIDOffset : mrConfigIDOffset+tdxabi.MrConfigIDSize])
}

// configHashFromMRCONFIGID unpacks SHA-256(config) || 16 zero bytes. A
// nonzero tail is rejected rather than ignored: it is a field the host chose
// and the guest would otherwise claim to have checked.
func configHashFromMRCONFIGID(field []byte) (string, error) {
	if len(field) != tdxabi.MrConfigIDSize {
		return "", fmt.Errorf("MRCONFIGID is %d bytes, expected %d", len(field), tdxabi.MrConfigIDSize)
	}
	tail := field[sha256.Size:]
	if !bytes.Equal(tail, make([]byte, len(tail))) {
		return "", fmt.Errorf("MRCONFIGID pads the config hash with %x, not zeros", tail)
	}
	return hex.EncodeToString(field[:sha256.Size]), nil
}
