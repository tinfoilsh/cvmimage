package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

func TestTLSExporterIsBoundIntoV3CryptoMaterial(t *testing.T) {
	var tlsKeyFP, hpkeKey [32]byte
	copy(tlsKeyFP[:], bytes.Repeat([]byte{0xaa}, len(tlsKeyFP)))
	copy(hpkeKey[:], bytes.Repeat([]byte{0xbb}, len(hpkeKey)))
	tlsExporter := bytes.Repeat([]byte{0xcc}, TLSExporterSize)

	cryptoMaterial, err := buildCryptoMaterialSection(tlsKeyFP, hpkeKey, tlsExporter)
	if err != nil {
		t.Fatalf("building crypto material: %v", err)
	}
	cryptoBytes, err := json.Marshal(cryptoMaterial)
	if err != nil {
		t.Fatalf("marshaling crypto material: %v", err)
	}
	deviceBytes, err := json.Marshal(envelope.DeviceEvidenceSection{
		Format: envelope.DeviceEvidenceV1Format,
		Items:  []envelope.DeviceEvidenceItem{},
	})
	if err != nil {
		t.Fatalf("marshaling device evidence: %v", err)
	}

	nonce := bytes.Repeat([]byte{0xdd}, envelope.NonceSize)
	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)
	reportData, err := envelope.ComputeReportData(nonce, cryptoHash[:], deviceHash[:])
	if err != nil {
		t.Fatalf("computing report data: %v", err)
	}
	docBytes, err := json.Marshal(envelope.Document{
		Format: envelope.AttestationV3Format,
		Challenge: envelope.Challenge{
			Nonce:               hex.EncodeToString(nonce),
			ReportData:          hex.EncodeToString(reportData[:]),
			ReportDataAlgorithm: envelope.ReportDataV1Algorithm,
		},
		CPUEvidence: envelope.CPUEvidence{
			Format:       envelope.TDXQuoteV1Format,
			ReportBase64: base64.StdEncoding.EncodeToString([]byte{0x01}),
			Endorsed: envelope.EndorsedHashes{
				CryptoMaterialHash: hex.EncodeToString(cryptoHash[:]),
				DeviceEvidenceHash: hex.EncodeToString(deviceHash[:]),
			},
		},
		CryptoMaterial: base64.StdEncoding.EncodeToString(cryptoBytes),
		DeviceEvidence: base64.StdEncoding.EncodeToString(deviceBytes),
		Collateral:     []envelope.CollateralEntry{},
	})
	if err != nil {
		t.Fatalf("marshaling document: %v", err)
	}

	parsed, _, err := envelope.Check(docBytes, nonce)
	if err != nil {
		t.Fatalf("checking v3 envelope: %v", err)
	}
	item, ok := parsed.CryptoMaterialItem(tlsExporterCryptoMaterialID)
	if !ok {
		t.Fatal("v3 envelope does not contain TLS exporter crypto material")
	}
	if item.Format != tlsExporterCryptoMaterialV1Format {
		t.Fatalf("TLS exporter format = %q, want %q", item.Format, tlsExporterCryptoMaterialV1Format)
	}
	if item.Data != hex.EncodeToString(tlsExporter) {
		t.Fatalf("TLS exporter data = %q, want %q", item.Data, hex.EncodeToString(tlsExporter))
	}
}

func TestBuildCryptoMaterialSectionRejectsInvalidTLSExporterSize(t *testing.T) {
	_, err := buildCryptoMaterialSection([32]byte{}, [32]byte{}, []byte{0x01})
	if err == nil {
		t.Fatal("expected an error for a TLS exporter with the wrong size")
	}
}
