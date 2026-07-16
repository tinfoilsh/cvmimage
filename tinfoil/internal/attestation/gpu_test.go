package attestation

import "testing"

func TestRequiresNVSwitchEvidence(t *testing.T) {
	tests := []struct {
		name     string
		arch     string
		gpuCount int
		want     bool
		wantErr  bool
	}{
		{"single hopper GPU never requires switch evidence", GPUArchHopper, 1, false, false},
		{"hopper 8 GPU requires switch evidence", GPUArchHopper, 8, true, false},
		{"hopper non-8 multi-GPU is an invalid shape", GPUArchHopper, 4, false, true},
		{"blackwell 8 GPU skips switch evidence", GPUArchBlackwell, 8, false, false},
		{"blackwell 4 GPU skips switch evidence", GPUArchBlackwell, 4, false, false},
		{"unknown multi-GPU arch is rejected", "UNKNOWN_123", 8, false, true},
		{"unknown single GPU is allowed without switch evidence", "UNKNOWN_123", 1, false, false},
		{"missing arch with no GPUs is allowed", "", 0, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RequiresNVSwitchEvidence(tt.arch, tt.gpuCount)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RequiresNVSwitchEvidence(%q, %d) error = %v, wantErr %v", tt.arch, tt.gpuCount, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("RequiresNVSwitchEvidence(%q, %d) = %v, want %v", tt.arch, tt.gpuCount, got, tt.want)
			}
		})
	}
}

func TestGPUEvidenceCollectionArch(t *testing.T) {
	var nilCollection *GPUEvidenceCollection
	if got := nilCollection.Arch(); got != "" {
		t.Fatalf("nil collection arch = %q, want empty", got)
	}
	collection := &GPUEvidenceCollection{Evidences: []GPUEvidence{{Arch: GPUArchHopper}}}
	if got := collection.Arch(); got != GPUArchHopper {
		t.Fatalf("arch = %q, want %q", got, GPUArchHopper)
	}
}
