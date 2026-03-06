package attestation

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	"github.com/klauspost/cpuid/v2"
	verifierattestation "github.com/tinfoilsh/tinfoil-go/verifier/attestation"
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

func gzipCompress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %v", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %v", err)
	}
	return b.Bytes(), nil
}

func sevReport(userData [64]byte) (*verifierattestation.Document, error) {
	qp, err := sevclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %v", err)
	}
	report, err := qp.GetRawQuote(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	if len(report) > sevabi.ReportSize {
		report = report[:sevabi.ReportSize]
	}

	compressedReport, err := gzipCompress(report)
	if err != nil {
		return nil, fmt.Errorf("failed to compress report: %v", err)
	}

	return &verifierattestation.Document{
		Format: verifierattestation.SevGuestV2,
		Body:   base64.StdEncoding.EncodeToString(compressedReport),
	}, nil
}

func tdxReport(userData [64]byte) (*verifierattestation.Document, error) {
	qp, err := tdxclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %v", err)
	}

	if err := qp.IsSupported(); err != nil {
		return nil, fmt.Errorf("TDX is not supported: %v", err)
	}

	report, err := qp.GetRawQuote(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	compressedReport, err := gzipCompress(report)
	if err != nil {
		return nil, fmt.Errorf("failed to compress report: %v", err)
	}

	return &verifierattestation.Document{
		Format: verifierattestation.TdxGuestV2,
		Body:   base64.StdEncoding.EncodeToString(compressedReport),
	}, nil
}

// Report fetches a hardware attestation report (SEV-SNP or TDX) binding the given user data.
func Report(userData [64]byte) (*verifierattestation.Document, error) {
	if cpuid.CPU.IsVendor(cpuid.AMD) {
		return sevReport(userData)
	} else if cpuid.CPU.IsVendor(cpuid.Intel) {
		return tdxReport(userData)
	}
	return nil, fmt.Errorf("attestation report for vendor %s not supported", cpuid.CPU.VendorString)
}

// DummyReport returns a non-cryptographic attestation document for dev/localhost use.
func DummyReport(userData [64]byte) *verifierattestation.Document {
	return &verifierattestation.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   hex.EncodeToString(userData[:]),
	}
}
