package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"tinfoil/internal/attestedkeys"
)

func publicWorkloadKey() envelope.CryptoMaterialItem {
	// Public Ed25519 RFC 8032 test vector, also used by sdk-flywheel P1.
	return envelope.CryptoMaterialItem{ID: "host-ssh", Format: attestedkeys.SPKIFormat, Data: "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"}
}

func TestEachNonceQuoteBindsCompletePublicInventory(t *testing.T) {
	body := BodyV2{TLSKeyFP: sha256.Sum256([]byte("tls")), HPKEKey: sha256.Sum256([]byte("hpke"))}
	workload := []envelope.CryptoMaterialItem{publicWorkloadKey()}
	material := body.CryptoMaterial(workload)
	workload[0].Data = "mutated after capture"
	if material[2] != publicWorkloadKey() {
		t.Fatal("inventory aliases caller storage")
	}
	var reports [][64]byte
	var previous string
	for _, nonce := range [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)} {
		// Capture the actual REPORT_DATA submitted to the quote provider. This
		// test validates assembly, not a simulated hardware trust decision.
		doc, err := buildAttestation(material, nonce, nil, nil, func(data [64]byte) ([]byte, string, error) {
			reports = append(reports, data)
			return []byte("quote-provider-output"), PlatformSEVSNP, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := base64.StdEncoding.DecodeString(doc.CryptoMaterial)
		if err != nil {
			t.Fatal(err)
		}
		var section envelope.CryptoMaterialSection
		if err := json.Unmarshal(encoded, &section); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(section.Items, material) {
			t.Fatal("quote omitted or changed material")
		}
		if previous != "" && previous != doc.CryptoMaterial {
			t.Fatal("nonce request rotated material")
		}
		previous = doc.CryptoMaterial
		devices, err := base64.StdEncoding.DecodeString(doc.DeviceEvidence)
		if err != nil {
			t.Fatal(err)
		}
		cmHash, deHash := sha256.Sum256(encoded), sha256.Sum256(devices)
		expected, err := envelope.ComputeReportData(nonce, cmHash[:], deHash[:])
		if err != nil {
			t.Fatal(err)
		}
		if reports[len(reports)-1] != expected || doc.Challenge.ReportData != hex.EncodeToString(expected[:]) || doc.CPUEvidence.Endorsed.CryptoMaterialHash != hex.EncodeToString(cmHash[:]) {
			t.Fatal("quoted bytes differ from complete endorsed section")
		}
	}
	if reports[0] == reports[1] {
		t.Fatal("fresh nonce was not bound")
	}
}

func TestInvalidMaterialRejectedBeforeQuote(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem
	}{
		{"duplicate builtin", func(items []envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem {
			items[2].ID = "tls"
			return items
		}},
		{"missing builtin", func(items []envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem { return items[1:] }},
		{"path id", func(items []envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem {
			items[2].ID = "../key"
			return items
		}},
		{"wrong format", func(items []envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem {
			items[2].Format = envelope.KeyX25519HPKEV1Format
			return items
		}},
		{"malformed public", func(items []envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem {
			items[2].Data = "deadbeef"
			return items
		}},
		{"wrong tls width", func(items []envelope.CryptoMaterialItem) []envelope.CryptoMaterialItem {
			items[0].Data = "ab"
			return items
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			items := test.mutate((BodyV2{}).CryptoMaterial([]envelope.CryptoMaterialItem{publicWorkloadKey()}))
			_, err := buildAttestation(items, make([]byte, 32), nil, nil, func([64]byte) ([]byte, string, error) {
				t.Fatal("invalid inventory reached quote provider")
				return nil, "", nil
			})
			if err == nil {
				t.Fatal("invalid material accepted")
			}
		})
	}
}
