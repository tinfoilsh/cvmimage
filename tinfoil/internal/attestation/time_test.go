package attestation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	"tinfoil/internal/trustedtime"
)

func testClockSample() trustedtime.Sample {
	return trustedtime.Sample{
		Time:        time.Date(2026, time.October, 1, 12, 0, 0, 123456789, time.UTC),
		Uncertainty: 25 * time.Millisecond,
	}
}

// checkBoundSections uses the pinned verifier to check the unchanged v3
// hash algorithm, independently of this producer. It does not authenticate
// a hardware signature or implement a v4 verifier.
func checkBoundSections(t *testing.T, doc *envelope.Document, nonce []byte) (*envelope.Document, [64]byte) {
	t.Helper()
	compat := *doc
	compat.Format = envelope.AttestationV3Format
	raw, err := json.Marshal(compat)
	if err != nil {
		t.Fatal(err)
	}
	parsed, reportData, err := envelope.Check(raw, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, reportData
}

func TestTimedAttestationBindsClockNonceAndChannelKeys(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, envelope.NonceSize)
	body := BodyV2{TLSKeyFP: [32]byte{1}, HPKEKey: [32]byte{2}}
	device := envelope.DeviceEvidenceItem{
		ID: "gpu-0", Kind: "gpu", Vendor: "nvidia", Format: envelope.NvidiaGPUEvidenceV1Format,
		Evidence: json.RawMessage(`{"nonce":"preserved"}`),
	}
	sample := testClockSample()
	clockReads := 0
	var quoted [64]byte
	doc, err := buildTimedAttestation(body.CryptoMaterial(), nonce, []envelope.DeviceEvidenceItem{device}, nil,
		func() (trustedtime.Sample, error) {
			clockReads++
			return sample, nil
		},
		func(data [64]byte) ([]byte, string, error) {
			if clockReads != 1 {
				t.Fatalf("quote requested after %d clock reads, want 1", clockReads)
			}
			quoted = data
			return []byte("hardware quote placeholder"), PlatformTDX, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != AttestationV4Format {
		t.Fatalf("format = %q", doc.Format)
	}
	parsed, checked := checkBoundSections(t, doc, nonce)
	if checked != quoted {
		t.Fatal("hardware quote input does not match the pinned verifier's recomputation")
	}
	for _, want := range body.CryptoMaterial() {
		got, ok := parsed.CryptoMaterialItem(want.ID)
		if !ok || *got != want {
			t.Fatalf("channel key %q was not preserved", want.ID)
		}
	}
	items := parsed.DeviceEvidenceItems()
	if len(items) != 2 || items[1].ID != GuestClockID || items[1].Kind != guestClockKind || items[1].Vendor != guestClockVendor || items[1].Format != GuestClockV1Format {
		t.Fatalf("unexpected clock evidence: %+v", items)
	}
	if items[0].ID != device.ID || items[0].Format != device.Format || !bytes.Equal(items[0].Evidence, device.Evidence) {
		t.Fatal("existing GPU evidence was not preserved")
	}
	var clock GuestClockEvidence
	if err := json.Unmarshal(items[1].Evidence, &clock); err != nil {
		t.Fatal(err)
	}
	if !clock.UTC.Equal(sample.Time) || clock.Status != clockSynchronized || clock.UncertaintyNanoseconds != int64(sample.Uncertainty) {
		t.Fatalf("clock claim = %+v, sample = %+v", clock, sample)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := envelope.Check(raw, nonce); err == nil {
		t.Fatal("a v3-only verifier accepted the v4 document")
	}

	for _, field := range []string{"utc", "status", "uncertainty_ns"} {
		t.Run("tampered "+field, func(t *testing.T) {
			var section envelope.DeviceEvidenceSection
			encoded, err := base64.StdEncoding.DecodeString(doc.DeviceEvidence)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &section); err != nil {
				t.Fatal(err)
			}
			var claim map[string]any
			if err := json.Unmarshal(section.Items[1].Evidence, &claim); err != nil {
				t.Fatal(err)
			}
			claim[field] = "tampered"
			section.Items[1].Evidence, err = json.Marshal(claim)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err = json.Marshal(section)
			if err != nil {
				t.Fatal(err)
			}
			tampered := *doc
			tampered.Format = envelope.AttestationV3Format
			tampered.DeviceEvidence = base64.StdEncoding.EncodeToString(encoded)
			raw, err := json.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := envelope.Check(raw, nonce); err == nil {
				t.Fatal("the pinned verifier accepted altered clock bytes")
			}
		})
	}
	for _, key := range []string{envelope.CryptoMaterialIDTLS, envelope.CryptoMaterialIDHPKE} {
		t.Run("different "+key+" key", func(t *testing.T) {
			changed := body
			if key == envelope.CryptoMaterialIDTLS {
				changed.TLSKeyFP[0]++
			} else {
				changed.HPKEKey[0]++
			}
			section, err := json.Marshal(envelope.CryptoMaterialSection{
				Format: envelope.CryptoMaterialV1Format, Items: changed.CryptoMaterial(),
			})
			if err != nil {
				t.Fatal(err)
			}
			tampered := *doc
			tampered.Format = envelope.AttestationV3Format
			tampered.CryptoMaterial = base64.StdEncoding.EncodeToString(section)
			raw, err := json.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := envelope.Check(raw, nonce); err == nil {
				t.Fatal("the pinned verifier accepted clock evidence with a different channel key")
			}
		})
	}

	t.Run("different challenge", func(t *testing.T) {
		wrongNonce := bytes.Repeat([]byte{0x43}, envelope.NonceSize)
		compat := *doc
		compat.Format = envelope.AttestationV3Format
		raw, err := json.Marshal(compat)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := envelope.Check(raw, wrongNonce); err == nil {
			t.Fatal("the pinned verifier accepted a different challenge")
		}
	})
}

func TestV3AttestationRetainsPinnedWireFormat(t *testing.T) {
	nonce := make([]byte, envelope.NonceSize)
	var quoted [64]byte
	doc, err := buildAttestation(BodyV2{}.CryptoMaterial(), nonce, nil, nil,
		func(data [64]byte) ([]byte, string, error) {
			quoted = data
			return []byte("hardware quote placeholder"), PlatformSEVSNP, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, reportData, err := envelope.Check(raw, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if reportData != quoted || len(parsed.DeviceEvidenceItems()) != 0 {
		t.Fatal("v3 quote binding or empty device section changed")
	}
}

func TestTimedAttestationRejectsUnavailableClockBeforeQuoting(t *testing.T) {
	for _, test := range []struct {
		name   string
		sample trustedtime.Sample
		err    error
	}{
		{name: "missing", err: errors.New("missing status")},
		{name: "stale", err: errors.New("stale status")},
		{name: "unsynchronized", err: errors.New("unsynchronized clock")},
		{name: "zero time"},
		{name: "negative uncertainty", sample: trustedtime.Sample{Time: testClockSample().Time, Uncertainty: -time.Nanosecond}},
		{name: "excess uncertainty", sample: trustedtime.Sample{Time: testClockSample().Time, Uncertainty: trustedtime.MaxUncertainty + time.Nanosecond}},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := buildTimedAttestation(BodyV2{}.CryptoMaterial(), make([]byte, envelope.NonceSize), nil, nil,
				func() (trustedtime.Sample, error) { return test.sample, test.err },
				func([64]byte) ([]byte, string, error) {
					t.Fatal("unavailable clock reached hardware quote generation")
					return nil, "", nil
				},
			)
			if doc != nil || !errors.Is(err, ErrClockUnavailable) {
				t.Fatalf("document = %v, error = %v", doc, err)
			}
		})
	}
}

func TestTimedAttestationValidatesChallengeBeforeReadingClock(t *testing.T) {
	doc, err := buildTimedAttestation(nil, nil, nil, nil,
		func() (trustedtime.Sample, error) {
			t.Fatal("clock read before accepting a valid challenge")
			return trustedtime.Sample{}, nil
		},
		func([64]byte) ([]byte, string, error) {
			t.Fatal("invalid challenge reached hardware quote generation")
			return nil, "", nil
		},
	)
	if err == nil || doc != nil {
		t.Fatalf("document = %v, error = %v", doc, err)
	}
}

func TestTimedAttestationRejectsDuplicateClockClaim(t *testing.T) {
	doc, err := buildTimedAttestation(BodyV2{}.CryptoMaterial(), make([]byte, envelope.NonceSize),
		[]envelope.DeviceEvidenceItem{{ID: GuestClockID, Evidence: json.RawMessage(`{}`)}}, nil,
		func() (trustedtime.Sample, error) { return testClockSample(), nil },
		func([64]byte) ([]byte, string, error) {
			t.Fatal("duplicate clock claim reached hardware quote generation")
			return nil, "", nil
		},
	)
	if err == nil || doc != nil {
		t.Fatalf("document = %v, error = %v", doc, err)
	}
}
