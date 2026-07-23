package boot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkStagePrecedesIdentityAndAttestation(t *testing.T) {
	positions := make(map[string]int, len(InitialStages))
	for index, stage := range InitialStages {
		positions[stage] = index
	}
	for _, stage := range []string{StageNetwork, StageIdentity, StageCPUAttestation} {
		if _, ok := positions[stage]; !ok {
			t.Fatalf("required stage %q is missing: %v", stage, InitialStages)
		}
	}
	if positions[StageNetwork] >= positions[StageIdentity] ||
		positions[StageNetwork] >= positions[StageCPUAttestation] {
		t.Fatalf("network stage must precede network-dependent boot work: %v", InitialStages)
	}
}

func TestWriteStateAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boot-state.json")

	payload := []byte(`{"stages":[],"started_at":"2026-01-01T00:00:00Z"}`)
	if err := writeStateAtomic(path, payload); err != nil {
		t.Fatalf("writeStateAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "boot-state.json" {
			t.Fatalf("leftover temp file %q in state dir", e.Name())
		}
	}
}

func TestFailureSummaryReturnsFirstFailedStage(t *testing.T) {
	state := &State{Stages: []Stage{
		{Name: StageNetwork, Status: StatusOK},
		{Name: StageCertificate, Status: StatusFailed, Detail: "issuer\nrejected request"},
		{Name: StageContainers, Status: StatusFailed, Detail: "later failure"},
	}}

	got, ok := state.FailureSummary()
	if !ok {
		t.Fatal("FailureSummary did not report a failed stage")
	}
	want := `boot stage "certificate" failed: "issuer\nrejected request"`
	if got != want {
		t.Fatalf("FailureSummary = %q, want %q", got, want)
	}
}

func TestFailureSummaryBoundsDetail(t *testing.T) {
	state := &State{Stages: []Stage{{
		Name:   StageNetwork,
		Status: StatusFailed,
		Detail: strings.Repeat("x", failureDetailLimit+100),
	}}}

	got, ok := state.FailureSummary()
	if !ok {
		t.Fatal("FailureSummary did not report a failed stage")
	}
	want := `boot stage "network" failed: "` + strings.Repeat("x", failureDetailLimit) + `..."`
	if got != want {
		t.Fatalf("FailureSummary = %q, want %q", got, want)
	}
}

func TestFailureSummaryRejectsMissingFailureIdentity(t *testing.T) {
	for _, state := range []*State{
		{Stages: []Stage{{Name: StageNetwork, Status: StatusOK}}},
		{Stages: []Stage{{Status: StatusFailed, Detail: "no stage"}}},
	} {
		if got, ok := state.FailureSummary(); ok || got != "" {
			t.Fatalf("FailureSummary = %q, %v; want empty, false", got, ok)
		}
	}
}
