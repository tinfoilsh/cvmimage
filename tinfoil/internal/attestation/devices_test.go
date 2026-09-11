package attestation

import "testing"

func TestNoDeviceEvidenceRejectsConfiguredDevices(t *testing.T) {
	for _, count := range []int{-1, 1, 8} {
		if _, err := NoDeviceEvidence([32]byte{}, count); err == nil {
			t.Fatalf("accepted %d devices without an evidence provider", count)
		}
	}
	if evidence, err := NoDeviceEvidence([32]byte{42}, 0); err != nil || len(evidence) != 0 {
		t.Fatalf("CPU-only evidence = %v, error = %v", evidence, err)
	}
}
