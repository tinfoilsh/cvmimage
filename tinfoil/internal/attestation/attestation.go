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
	"regexp"
	"strings"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	"tinfoil/internal/attestedkeys"
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
}

// CryptoMaterial combines the unchanged built-in identities with the complete
// boot inventory. Every v3 quote producer must supply that same inventory.
func (a BodyV2) CryptoMaterial(workload []envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem {
	items := []envelope.CryptoMaterialItem{
		{ID: envelope.CryptoMaterialIDTLS, Format: envelope.KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(a.TLSKeyFP[:])},
		{ID: envelope.CryptoMaterialIDHPKE, Format: envelope.KeyX25519HPKEV1Format, Data: hex.EncodeToString(a.HPKEKey[:])},
	}
	return append(items, workload...)
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
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral []envelope.CollateralEntry,
) (*envelope.Document, error) {
	return buildAttestation(material, nonce, deviceEvidence, collateral, reportWithRetry)
}

func buildAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral []envelope.CollateralEntry,
	quote func([64]byte) ([]byte, string, error),
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
	if err := validateCryptoMaterial(material); err != nil {
		return nil, err
	}

	cryptoMaterial := envelope.CryptoMaterialSection{
		Format: envelope.CryptoMaterialV1Format,
		Items:  material,
	}
	deviceSection := envelope.DeviceEvidenceSection{
		Format: envelope.DeviceEvidenceV1Format,
		Items:  deviceEvidence,
	}
	if err := rejectInvalidItemIDs(deviceSection.Items); err != nil {
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

	rawQuote, platform, err := quote(reportData)
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

var materialID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func validateCryptoMaterial(items []envelope.CryptoMaterialItem) error {
	if len(items) < 2 || len(items) > 34 {
		return fmt.Errorf("invalid crypto_material inventory size")
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if !materialID.MatchString(item.ID) || seen[item.ID] {
			return fmt.Errorf("invalid or duplicate crypto_material id %q", item.ID)
		}
		seen[item.ID] = true
		switch item.ID {
		case envelope.CryptoMaterialIDTLS, envelope.CryptoMaterialIDHPKE:
			format := envelope.KeySPKIFPSHA256V1Format
			if item.ID == envelope.CryptoMaterialIDHPKE {
				format = envelope.KeyX25519HPKEV1Format
			}
			data, err := hex.DecodeString(item.Data)
			if err != nil || len(data) != 32 || item.Data != strings.ToLower(item.Data) || item.Format != format {
				return fmt.Errorf("invalid built-in crypto_material %q", item.ID)
			}
		default:
			if item.Format != attestedkeys.SPKIFormat {
				return fmt.Errorf("invalid workload key format for %q", item.ID)
			}
			if err := attestedkeys.ValidatePublic(item.Data, ""); err != nil {
				return fmt.Errorf("crypto_material %q: %w", item.ID, err)
			}
		}
	}
	if !seen[envelope.CryptoMaterialIDTLS] || !seen[envelope.CryptoMaterialIDHPKE] {
		return fmt.Errorf("missing built-in crypto_material")
	}
	return nil
}

// rejectInvalidItemIDs enforces the builder-side rules verifiers hold item
// ids to: non-empty and unique within the section.
func rejectInvalidItemIDs(items []envelope.DeviceEvidenceItem) error {
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if item.ID == "" {
			return fmt.Errorf("device_evidence item has an empty id")
		}
		if seen[item.ID] {
			return fmt.Errorf("duplicate device_evidence item id %q", item.ID)
		}
		seen[item.ID] = true
	}
	return nil
}
