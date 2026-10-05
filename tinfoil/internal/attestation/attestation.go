// Package attestation produces the enclave's attestation documents: it
// acquires hardware quotes and assembles the v3 document served at the
// well-known endpoint. Wire shapes (document, sections, collateral entries,
// format URIs) and all verification logic live in tinfoil-go; this package
// owns only the production side.
package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	envelope "github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"

	"tinfoil/internal/legacy"

	"tinfoil/internal/compress"
)

const (
	PlatformDummy  = "dummy"
	PlatformSEVSNP = "sev-snp"
	PlatformTDX    = "tdx"
)

type BodyV2 struct {
	TLSKeyFP [32]byte
	HPKEKey  [32]byte
	// Workload keys are endorsed by v3 quotes only; Marshal omits them.
	Workload []envelope.CryptoMaterialItem
}

func (a BodyV2) CryptoMaterial() []envelope.CryptoMaterialItem {
	items := []envelope.CryptoMaterialItem{
		{ID: envelope.CryptoMaterialIDTLS, Format: envelope.KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(a.TLSKeyFP[:])},
		{ID: envelope.CryptoMaterialIDHPKE, Format: envelope.KeyX25519HPKEV1Format, Data: hex.EncodeToString(a.HPKEKey[:])},
	}
	return append(items, a.Workload...)
}

func (a BodyV2) Marshal() [64]byte {
	var result [64]byte
	copy(result[:32], a.TLSKeyFP[:])
	copy(result[32:], a.HPKEKey[:])
	return result
}

// Guest device paths, one per platform.
const (
	SEVGuestDevice = "/dev/sev-guest"
	TDXGuestDevice = "/dev/tdx_guest"
)

// DevicePlatform names the platform from the guest device present, without
// opening it.
func DevicePlatform() (string, error) {
	if _, err := os.Stat(SEVGuestDevice); err == nil {
		return PlatformSEVSNP, nil
	}
	if _, err := os.Stat(TDXGuestDevice); err == nil {
		return PlatformTDX, nil
	}
	return "", fmt.Errorf("no attestation device found (checked %s, %s)", SEVGuestDevice, TDXGuestDevice)
}

// Report fetches the raw hardware attestation report and platform identifier.
func Report(userData [64]byte) (report []byte, platform string, err error) {
	platform, err = DevicePlatform()
	if err != nil {
		return nil, "", err
	}
	switch platform {
	case PlatformSEVSNP:
		var qp sevclient.LinuxConfigFsQuoteProvider
		report, err = qp.GetRawQuote(userData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote: %w", err)
		}
		if len(report) > sevabi.ReportSize {
			report = report[:sevabi.ReportSize]
		}
		return report, PlatformSEVSNP, nil
	case PlatformTDX:
		var qp tdxclient.QuoteProvider
		qp, err = tdxclient.GetQuoteProvider()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote provider: %w", err)
		}
		if err = qp.IsSupported(); err != nil {
			return nil, "", fmt.Errorf("TDX is not supported: %w", err)
		}
		report, err = qp.GetRawQuote(userData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote: %w", err)
		}
		return report, PlatformTDX, nil
	default:
		return nil, "", fmt.Errorf("unsupported platform %q", platform)
	}
}

const (
	quoteRetries    = 3
	quoteRetryDelay = 50 * time.Millisecond
)

// reportWithRetry calls Report with a bounded retry. Quote generation
// serializes on a single in-guest buffer (and, for TDX, a host round trip),
// so concurrent attestation requests can fail transiently with EINTR/EBUSY;
// a short retry absorbs that contention instead of surfacing it to clients.
func reportWithRetry(userData [64]byte) (report []byte, platform string, err error) {
	for attempt := 0; ; attempt++ {
		report, platform, err = Report(userData)
		if err == nil || attempt == quoteRetries {
			return report, platform, err
		}
		time.Sleep(quoteRetryDelay * time.Duration(attempt+1))
	}
}

// evidenceFormat maps a platform label to its CPU evidence format URI.
func evidenceFormat(platform string) (string, error) {
	switch platform {
	case PlatformSEVSNP:
		return envelope.SEVSNPReportV1Format, nil
	case PlatformTDX:
		return envelope.TDXQuoteV1Format, nil
	default:
		return "", fmt.Errorf("unsupported platform %q for v3 evidence", platform)
	}
}

// V2Document wraps a raw report into the legacy V2 format (base64+gzip).
func V2Document(rawReport []byte, platform string) (*legacy.Document, error) {
	compressed, err := compress.Gzip(rawReport)
	if err != nil {
		return nil, fmt.Errorf("failed to compress report: %w", err)
	}
	var format legacy.PredicateType
	switch platform {
	case PlatformSEVSNP:
		format = legacy.SevGuestV2
	case PlatformTDX:
		format = legacy.TdxGuestV2
	default:
		return nil, fmt.Errorf("unsupported platform for V2: %s", platform)
	}
	return &legacy.Document{
		Format: format,
		Body:   base64.StdEncoding.EncodeToString(compressed),
	}, nil
}

// DummyReport returns a non-cryptographic attestation document for dev/localhost use.
func DummyReport(userData [64]byte) *legacy.Document {
	return &legacy.Document{
		Format: legacy.DummyV2,
		Body:   hex.EncodeToString(userData[:]),
	}
}

// BuildAttestation assembles a fresh v3 attestation document: it serializes
// the two endorsed sections exactly once, derives REPORT_DATA from their
// hashes and the nonce, obtains a hardware quote over that REPORT_DATA, and
// returns the complete document. The endorsed sections are carried
// base64-encoded so verifiers recover the exact hashed bytes with a plain
// decode.
func BuildAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral []collateral.Entry,
) (json.RawMessage, error) {
	return envelope.Build(envelope.BuildInput{
		Nonce: nonce, CryptoMaterial: material, DeviceEvidence: deviceEvidence, Collateral: collateral,
	}, func(reportData [64]byte) (string, []byte, error) {
		rawQuote, platform, err := reportWithRetry(reportData)
		if err != nil {
			return "", nil, fmt.Errorf("obtaining hardware quote: %w", err)
		}
		format, err := evidenceFormat(platform)
		return format, rawQuote, err
	})
}
