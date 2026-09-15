package boot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCompleteFailurePreservesModelFailureAfterCertificateSuccess(t *testing.T) {
	state := NewTracker(InitialStages).state
	certificate := Stage{Name: StageCertificate, Status: StatusOK, Duration: 20 * time.Second}
	models := Stage{
		Name: StageModels, Status: StatusFailed, Duration: 25 * time.Millisecond,
		Detail: "mount model: input/output error",
		Stages: []Stage{{Name: "glm", Status: StatusFailed, Detail: "dm-verity corruption"}},
	}
	state.Stages[fixedStageIndex(t, StageCertificate)] = certificate
	state.Stages[fixedStageIndex(t, StageModels)] = models
	path := filepath.Join(t.TempDir(), "boot-state.json")
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := completeFailure(path); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasFailed() || !got.IsComplete() || got.CompletedAt.IsZero() {
		t.Fatalf("failure was not finalized: %+v", got)
	}
	if !got.StartedAt.Equal(state.StartedAt) {
		t.Fatalf("started_at changed: %v", got.StartedAt)
	}
	for _, stage := range got.Stages {
		switch stage.Name {
		case StageCertificate:
			if !reflect.DeepEqual(stage, certificate) {
				t.Fatalf("certificate result changed: %+v", stage)
			}
		case StageModels:
			if !reflect.DeepEqual(stage, models) {
				t.Fatalf("model failure changed: %+v", stage)
			}
		default:
			if stage.Status != StatusSkipped || stage.Detail == "" {
				t.Fatalf("unresolved stage was not skipped with a reason: %+v", stage)
			}
		}
	}
	if err := completeFailure(path); err != nil {
		t.Fatal(err)
	}
	again, err := loadState(path)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("finalizing twice changed state: %+v, %v", again, err)
	}
}

func TestCompleteFailureRequiresRecordedFailure(t *testing.T) {
	for _, status := range []string{StatusPending, StatusOK} {
		t.Run(status, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "boot-state.json")
			payload := []byte(`{"stages":[{"name":"certificate","status":"` + status + `"}]}`)
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if err := completeFailure(path); err == nil {
				t.Fatal("finalized boot without a recorded failure")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != string(payload) {
				t.Fatalf("state changed: %s, %v", got, err)
			}
		})
	}
}

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
	state := fixedBootState()
	state.Stages[fixedStageIndex(t, StageCertificate)] = Stage{
		Name: StageCertificate, Status: StatusFailed, Detail: "issuer\nrejected request",
	}
	state.Stages[fixedStageIndex(t, StageContainers)] = Stage{
		Name: StageContainers, Status: StatusFailed, Detail: "later failure",
	}

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
	state := fixedBootState()
	state.Stages[fixedStageIndex(t, StageNetwork)] = Stage{
		Name:   StageNetwork,
		Status: StatusFailed,
		Detail: strings.Repeat("x", failureDetailLimit+100),
	}

	got, ok := state.FailureSummary()
	if !ok {
		t.Fatal("FailureSummary did not report a failed stage")
	}
	want := `boot stage "network" failed: "` + strings.Repeat("x", failureDetailLimit) + `..."`
	if got != want {
		t.Fatalf("FailureSummary = %q, want %q", got, want)
	}
}

func TestFailureSummaryRequiresExactInitialStages(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]Stage) []Stage
	}{
		{
			name: "incomplete",
			mutate: func(stages []Stage) []Stage {
				return stages[:len(stages)-1]
			},
		},
		{
			name: "reordered",
			mutate: func(stages []Stage) []Stage {
				stages[0], stages[1] = stages[1], stages[0]
				return stages
			},
		},
		{
			name: "unknown",
			mutate: func(stages []Stage) []Stage {
				stages[0].Name = "unknown-stage"
				return stages
			},
		},
		{
			name: "extra",
			mutate: func(stages []Stage) []Stage {
				return append(stages, Stage{Name: "extra-stage", Status: StatusFailed})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := fixedBootState()
			state.Stages[0].Status = StatusFailed
			state.Stages[0].Detail = "must not be trusted"
			state.Stages = test.mutate(state.Stages)
			if got, ok := state.FailureSummary(); ok || got != "" {
				t.Fatalf("FailureSummary = %q, %v; want empty, false", got, ok)
			}
		})
	}
}

func TestBoundedStateTextPreservesInvalidUTF8(t *testing.T) {
	value := string([]byte{'a', 0xff, 'b', 'c'})
	if got := boundedStateText(value, len(value)); got != value {
		t.Fatalf("boundedStateText changed untruncated bytes: %q", []byte(got))
	}
	want := string([]byte{'a', 0xff, 'b'}) + "..."
	if got := boundedStateText(value, 3); got != want {
		t.Fatalf("boundedStateText = %q, want %q", []byte(got), []byte(want))
	}
}

func TestBoundedStateTextDoesNotSplitValidUTF8(t *testing.T) {
	if got, want := boundedStateText("ab€cd", 4), "ab..."; got != want {
		t.Fatalf("boundedStateText = %q, want %q", got, want)
	}
}

func fixedBootState() *State {
	stages := make([]Stage, len(InitialStages))
	for index, name := range InitialStages {
		stages[index] = Stage{Name: name, Status: StatusOK}
	}
	return &State{Stages: stages}
}

func fixedStageIndex(t *testing.T, name string) int {
	t.Helper()
	for index, stage := range InitialStages {
		if stage == name {
			return index
		}
	}
	t.Fatalf("fixed stage %q not found", name)
	return -1
}
