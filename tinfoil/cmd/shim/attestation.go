package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	"github.com/klauspost/cpuid/v2"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

type AttestationBodyV2 struct {
	TLSKeyFP [32]byte
	HPKEKey  [32]byte
}

func (a AttestationBodyV2) Marshal() [64]byte {
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

// sevAttestationReport gets a SEV-SNP signed attestation report over a TLS certificate fingerprint
func sevAttestationReport(userData [64]byte) (*attestation.Document, error) {
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

	// Compress the report data
	compressedReport, err := gzipCompress(report)
	if err != nil {
		return nil, fmt.Errorf("failed to compress report: %v", err)
	}

	return &attestation.Document{
		Format: attestation.SevGuestV2,
		Body:   base64.StdEncoding.EncodeToString(compressedReport),
	}, nil
}

// tdxAttestationReport gets a TDX signed attestation report over a TLS certificate fingerprint
func tdxAttestationReport(userData [64]byte) (*attestation.Document, error) {
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

	// Compress the report data
	compressedReport, err := gzipCompress(report)
	if err != nil {
		return nil, fmt.Errorf("failed to compress report: %v", err)
	}

	return &attestation.Document{
		Format: attestation.TdxGuestV2,
		Body:   base64.StdEncoding.EncodeToString(compressedReport),
	}, nil
}

func attestationReport(userData [64]byte) (*attestation.Document, error) {
	if cpuid.CPU.IsVendor(cpuid.AMD) {
		log.Info("Requesting AMD SEV-SNP quote")
		return sevAttestationReport(userData)
	} else if cpuid.CPU.IsVendor(cpuid.Intel) {
		log.Info("Requesting Intel TDX quote")
		return tdxAttestationReport(userData)
	} else {
		return nil, fmt.Errorf("attestation report for vendor %s not supported", cpuid.CPU.VendorString)
	}
}
