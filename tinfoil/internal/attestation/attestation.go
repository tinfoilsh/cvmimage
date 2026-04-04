package attestation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
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

const AttestationFormat = "https://tinfoil.sh/predicate/attestation/v3"

type Attestation struct {
	Format      string          `json:"format"`
	ReportData  ReportDataInfo  `json:"report_data"`
	CPU         CPUReport       `json:"cpu"`
	GPU         json.RawMessage `json:"gpu,omitempty"`
	NVSwitch    json.RawMessage `json:"nvswitch,omitempty"`
	Certificate string          `json:"certificate"`
	Signature   string          `json:"signature"`
}

type ReportDataInfo struct {
	TLSKeyFP             string `json:"tls_key_fp"`
	HPKEKey              string `json:"hpke_key"`
	Nonce                string `json:"nonce"`
	GPUEvidenceHash      string `json:"gpu_evidence_hash,omitempty"`
	NVSwitchEvidenceHash string `json:"nvswitch_evidence_hash,omitempty"`
}

type CPUReport struct {
	Platform string `json:"platform"`
	Report   string `json:"report"`
}

// ComputeReportData computes the 64-byte REPORT_DATA as:
//
//	SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
//
// padded to 64 bytes with zeros.
func ComputeReportData(tlsKeyFP [32]byte, hpkeKey [32]byte, nonce []byte, gpuEvidenceHash []byte, nvswitchEvidenceHash []byte) [64]byte {
	h := sha256.New()
	h.Write(tlsKeyFP[:])
	h.Write(hpkeKey[:])
	h.Write(nonce)
	h.Write(gpuEvidenceHash)
	h.Write(nvswitchEvidenceHash)
	var result [64]byte
	copy(result[:32], h.Sum(nil))
	return result
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}

// EvidenceHash computes SHA-256 over raw evidence JSON. Returns nil for empty input.
func EvidenceHash(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	h := sha256.Sum256(data)
	return h[:]
}

// RandomNonce generates a cryptographically random 32-byte nonce.
func RandomNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating random nonce: %w", err)
	}
	return nonce, nil
}

// BuildAttestation constructs and signs a fresh attestation document.
// It collects a fresh CPU report with evidence hashes bound into REPORT_DATA,
// then signs the entire payload with the TLS private key.
func BuildAttestation(
	tlsKeyFP [32]byte,
	hpkeKey [32]byte,
	nonce []byte,
	gpuJSON json.RawMessage,
	nvswitchJSON json.RawMessage,
	tlsCert *tls.Certificate,
) (*Attestation, error) {
	gpuHash := EvidenceHash(gpuJSON)
	nvswitchHash := EvidenceHash(nvswitchJSON)
	reportData := ComputeReportData(tlsKeyFP, hpkeKey, nonce, gpuHash, nvswitchHash)

	rawReport, platform, err := Report(reportData)
	if err != nil {
		return nil, fmt.Errorf("fetching CPU attestation report: %w", err)
	}

	// Encode the TLS leaf certificate as PEM
	certPEM := ""
	if tlsCert != nil && len(tlsCert.Certificate) > 0 {
		certPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCert.Certificate[0],
		}))
	}

	att := &Attestation{
		Format: AttestationFormat,
		ReportData: ReportDataInfo{
			TLSKeyFP:             hex.EncodeToString(tlsKeyFP[:]),
			HPKEKey:              hex.EncodeToString(hpkeKey[:]),
			Nonce:                hex.EncodeToString(nonce),
			GPUEvidenceHash:      hexOrEmpty(gpuHash),
			NVSwitchEvidenceHash: hexOrEmpty(nvswitchHash),
		},
		CPU: CPUReport{
			Platform: platform,
			Report:   base64.StdEncoding.EncodeToString(rawReport),
		},
		GPU:         gpuJSON,
		NVSwitch:    nvswitchJSON,
		Certificate: certPEM,
	}

	sig, err := signAttestation(att, tlsCert)
	if err != nil {
		return nil, fmt.Errorf("signing attestation: %w", err)
	}
	att.Signature = sig

	return att, nil
}

// signAttestation signs the document with the TLS private key.
// The signature covers SHA-256 of the JSON-serialized document (with signature field empty).
func signAttestation(att *Attestation, tlsCert *tls.Certificate) (string, error) {
	if tlsCert == nil || tlsCert.PrivateKey == nil {
		return "", fmt.Errorf("TLS certificate or private key is nil, cannot sign attestation")
	}
	ecKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("TLS key is not ECDSA")
	}

	data, err := json.Marshal(att)
	if err != nil {
		return "", fmt.Errorf("marshaling for signing: %w", err)
	}
	digest := sha256.Sum256(data)

	sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("ECDSA sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}
