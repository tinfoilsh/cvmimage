package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	"github.com/klauspost/cpuid/v2"
	verifierattestation "github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	"tinfoil/internal/compress"
)

const (
	PlatformSEVSNP = "sev-snp"
	PlatformTDX    = "tdx"
)

type BodyV2 struct {
	TLSKeyFP [32]byte
	HPKEKey  [32]byte
}

func (a BodyV2) Marshal() [64]byte {
	var result [64]byte
	copy(result[:32], a.TLSKeyFP[:])
	copy(result[32:], a.HPKEKey[:])
	return result
}

// Report fetches the raw hardware attestation report and platform identifier.
func Report(userData [64]byte) (report []byte, platform string, err error) {
	if cpuid.CPU.IsVendor(cpuid.AMD) {
		qp, err := sevclient.GetQuoteProvider()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote provider: %w", err)
		}
		report, err := qp.GetRawQuote(userData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote: %w", err)
		}
		if len(report) > sevabi.ReportSize {
			report = report[:sevabi.ReportSize]
		}
		return report, PlatformSEVSNP, nil
	} else if cpuid.CPU.IsVendor(cpuid.Intel) {
		qp, err := tdxclient.GetQuoteProvider()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote provider: %w", err)
		}
		if err := qp.IsSupported(); err != nil {
			return nil, "", fmt.Errorf("TDX is not supported: %w", err)
		}
		report, err := qp.GetRawQuote(userData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote: %w", err)
		}
		return report, PlatformTDX, nil
	}
	return nil, "", fmt.Errorf("attestation report for vendor %s not supported", cpuid.CPU.VendorString)
}

// V2Document wraps a raw report into the legacy V2 format (base64+gzip).
func V2Document(rawReport []byte, platform string) (*verifierattestation.Document, error) {
	compressed, err := compress.Gzip(rawReport)
	if err != nil {
		return nil, fmt.Errorf("failed to compress report: %w", err)
	}
	var format verifierattestation.PredicateType
	switch platform {
	case PlatformSEVSNP:
		format = verifierattestation.SevGuestV2
	case PlatformTDX:
		format = verifierattestation.TdxGuestV2
	default:
		return nil, fmt.Errorf("unsupported platform for V2: %s", platform)
	}
	return &verifierattestation.Document{
		Format: format,
		Body:   base64.StdEncoding.EncodeToString(compressed),
	}, nil
}

// DummyReport returns a non-cryptographic attestation document for dev/localhost use.
func DummyReport(userData [64]byte) *verifierattestation.Document {
	return &verifierattestation.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   hex.EncodeToString(userData[:]),
	}
}
