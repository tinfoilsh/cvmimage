package main

import (
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
// hash followed by 16 zero bytes. It sits in TDINFO_STRUCT, which follows
// REPORTMACSTRUCT and TEE_TCB_INFO in a TD report, behind ATTRIBUTES, XFAM and
// MRTD. TDINFO_STRUCT gives those three the same widths TDQUOTEBODY does, so
// the library's sizes place the field.
const (
	reportMACStructSize = 256      // REPORTMACSTRUCT
	teeTCBInfoSize      = 239 + 17 // TEE_TCB_INFO and the reserved bytes after it
	tdInfoOffset        = reportMACStructSize + teeTCBInfoSize
	mrConfigIDOffset    = tdInfoOffset + tdxabi.TdAttributesSize + tdxabi.XfamSize + tdxabi.MrTdSize
)

// measuredConfigHash reads the config hash the host committed to at launch.
// Neither branch binds a key; the report is read for the one field.
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
	device := &tdxclient.LinuxDevice{}
	if err := device.Open(attestation.TDXGuestDevice); err != nil {
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
	return configHashFromTDReport(request.TdReport[:])
}

// configHashFromTDReport cuts MRCONFIGID out of a TD report. MRTD and MROWNER
// are its neighbours, and a host chooses MROWNER, so reading past either end
// would hand the config hash to whoever laid the report out.
func configHashFromTDReport(report []byte) (string, error) {
	if len(report) != tdxlabi.TdReportSize {
		return "", fmt.Errorf("TD report is %d bytes, expected %d", len(report), tdxlabi.TdReportSize)
	}
	return configHashFromMRCONFIGID(report[mrConfigIDOffset : mrConfigIDOffset+tdxabi.MrConfigIDSize])
}

// configHashFromMRCONFIGID unpacks SHA-256(config) || 16 zero bytes, the one
// encoding the compiler emits. A nonzero tail is refused rather than ignored:
// the host chose those bytes, and a verifier pins all 48.
func configHashFromMRCONFIGID(field []byte) (string, error) {
	if len(field) != tdxabi.MrConfigIDSize {
		return "", fmt.Errorf("MRCONFIGID is %d bytes, expected %d", len(field), tdxabi.MrConfigIDSize)
	}
	for _, pad := range field[sha256.Size:] {
		if pad != 0 {
			return "", fmt.Errorf("MRCONFIGID pads the config hash with %x, not zeros", field[sha256.Size:])
		}
	}
	return hex.EncodeToString(field[:sha256.Size]), nil
}
