// Package attestation produces the enclave's attestation documents: it
// acquires hardware quotes and assembles the v3 document served at the
// well-known endpoint. Wire shapes (document, sections, collateral entries,
// format URIs) and all verification logic live in tinfoil-go; this package
// owns only the production side.
package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	"tinfoil/internal/legacy"

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
	if _, statErr := os.Stat("/dev/sev-guest"); statErr == nil {
		var qp sevclient.QuoteProvider
		qp, err = sevclient.GetQuoteProvider()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote provider: %w", err)
		}
		report, err = qp.GetRawQuote(userData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote: %w", err)
		}
		if len(report) > sevabi.ReportSize {
			report = report[:sevabi.ReportSize]
		}
		return report, PlatformSEVSNP, nil
	} else if _, statErr := os.Stat("/dev/tdx_guest"); statErr == nil {
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
	}
	return nil, "", fmt.Errorf("no attestation device found (checked /dev/sev-guest, /dev/tdx_guest)")
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
	tlsKeyFP [32]byte,
	hpkeKey [32]byte,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral []envelope.CollateralEntry,
) (*envelope.Document, error) {
	if len(nonce) != envelope.NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", envelope.NonceSize, len(nonce))
	}
	if deviceEvidence == nil {
		deviceEvidence = []envelope.DeviceEvidenceItem{}
	}
	if collateral == nil {
		collateral = []envelope.CollateralEntry{}
	}

	cryptoMaterial := envelope.CryptoMaterialSection{
		Format: envelope.CryptoMaterialV1Format,
		Items: []envelope.CryptoMaterialItem{
			{
				ID:     envelope.CryptoMaterialIDTLS,
				Format: envelope.KeySPKIFPSHA256V1Format,
				Data:   hex.EncodeToString(tlsKeyFP[:]),
			},
			{
				ID:     envelope.CryptoMaterialIDHPKE,
				Format: envelope.KeyX25519HPKEV1Format,
				Data:   hex.EncodeToString(hpkeKey[:]),
			},
		},
	}
	deviceSection := envelope.DeviceEvidenceSection{
		Format: envelope.DeviceEvidenceV1Format,
		Items:  deviceEvidence,
	}
	if err := rejectDuplicateItemIDs(deviceSection.Items); err != nil {
		return nil, err
	}

	cryptoBytes, err := json.Marshal(cryptoMaterial)
	if err != nil {
		return nil, fmt.Errorf("serializing crypto_material: %w", err)
	}
	deviceBytes, err := json.Marshal(deviceSection)
	if err != nil {
		return nil, fmt.Errorf("serializing device_evidence: %w", err)
	}

	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)
	reportData, err := envelope.ComputeReportData(nonce, cryptoHash[:], deviceHash[:])
	if err != nil {
		return nil, err
	}

	rawQuote, platform, err := reportWithRetry(reportData)
	if err != nil {
		return nil, fmt.Errorf("obtaining hardware quote: %w", err)
	}
	format, err := evidenceFormat(platform)
	if err != nil {
		return nil, err
	}

	return &envelope.Document{
		Format: envelope.AttestationV3Format,
		Challenge: envelope.Challenge{
			Nonce:               hex.EncodeToString(nonce),
			ReportData:          hex.EncodeToString(reportData[:]),
			ReportDataAlgorithm: envelope.ReportDataV1Algorithm,
		},
		CPUEvidence: envelope.CPUEvidence{
			Format:       format,
			ReportBase64: base64.StdEncoding.EncodeToString(rawQuote),
			Endorsed: envelope.EndorsedHashes{
				CryptoMaterialHash: hex.EncodeToString(cryptoHash[:]),
				DeviceEvidenceHash: hex.EncodeToString(deviceHash[:]),
			},
		},
		CryptoMaterial: base64.StdEncoding.EncodeToString(cryptoBytes),
		DeviceEvidence: base64.StdEncoding.EncodeToString(deviceBytes),
		Collateral:     collateral,
	}, nil
}

// rejectDuplicateItemIDs enforces the builder-side rule that item ids within
// an endorsed section are unique (verifiers reject such documents).
func rejectDuplicateItemIDs(items []envelope.DeviceEvidenceItem) error {
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if seen[item.ID] {
			return fmt.Errorf("duplicate device_evidence item id %q", item.ID)
		}
		seen[item.ID] = true
	}
	return nil
}
