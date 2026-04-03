package boot

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type State struct {
	Stages      []Stage   `json:"stages"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type Stage struct {
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Duration time.Duration `json:"duration_ns"`
	Detail   string        `json:"detail,omitempty"`
	Stages   []Stage       `json:"stages,omitempty"`
}

const (
	StatusPending = "pending"
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusWarning = "warning"
	StatusFailed  = "failed"
)

const (
	StageConfig         = "config"
	StageIdentity       = "identity"
	StageCPUAttestation = "cpu-attestation"
	StageGPUAttestation = "gpu-attestation"
	StageCertificate    = "certificate"
	StageRegistryAuth   = "registry-auth"
	StageModels         = "models"
	StageContainers     = "containers"
	StageShim           = "shim"
)

// InitialStages is the ordered list of stages known at boot time.
// Both boot and shim use this as the starting point.
var InitialStages = []string{
	StageConfig, StageIdentity, StageCPUAttestation, StageGPUAttestation,
	StageCertificate, StageRegistryAuth, StageModels, StageContainers, StageShim,
}

// Tracker records boot stages as they complete.
type Tracker struct {
	state State
}

// NewTracker creates a tracker with the given stages pre-registered as pending.
func NewTracker(stages []string) *Tracker {
	s := make([]Stage, len(stages))
	for i, name := range stages {
		s[i] = Stage{Name: name, Status: StatusPending}
	}
	return &Tracker{
		state: State{Stages: s, StartedAt: time.Now()},
	}
}

// Record updates an existing stage by name or appends a new one. Auto-flushes.
func (t *Tracker) Record(name, status string, duration time.Duration, detail string) {
	stage := Stage{Name: name, Status: status, Duration: duration, Detail: detail}
	updated := false
	for i := range t.state.Stages {
		if t.state.Stages[i].Name == name {
			stage.Stages = t.state.Stages[i].Stages
			t.state.Stages[i] = stage
			updated = true
			break
		}
	}
	if !updated {
		t.state.Stages = append(t.state.Stages, stage)
	}
	if err := t.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to flush boot state: %v\n", err)
	}
}

// RecordSubstages sets the substages on an existing stage and flushes.
func (t *Tracker) RecordSubstages(name string, substages []Stage) {
	for i := range t.state.Stages {
		if t.state.Stages[i].Name == name {
			t.state.Stages[i].Stages = substages
			break
		}
	}
	if err := t.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to flush boot state: %v\n", err)
	}
}

// Flush writes the current boot state to disk without setting CompletedAt.
func (t *Tracker) Flush() error {
	data, err := json.MarshalIndent(t.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling boot state: %w", err)
	}
	if err := os.WriteFile(StatePath, data, 0644); err != nil {
		return fmt.Errorf("writing boot state: %w", err)
	}
	return nil
}

// Load reads the boot state from the ramdisk.
func Load() (*State, error) {
	data, err := os.ReadFile(StatePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", StatePath, err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing boot state: %w", err)
	}
	return &state, nil
}

// IsComplete returns true if all stages have resolved (no pending stages).
func (s *State) IsComplete() bool {
	for _, stage := range s.Stages {
		if stage.Status == StatusPending {
			return false
		}
	}
	return len(s.Stages) > 0
}

// HasFailed returns true if any stage has a "failed" status.
func (s *State) HasFailed() bool {
	for _, stage := range s.Stages {
		if stage.Status == StatusFailed {
			return true
		}
	}
	return false
}

// RecordStage loads the current state from disk, updates or appends a stage,
// and writes it back. Safe to call from a separate process after boot has exited.
func RecordStage(name, status string, duration time.Duration, detail string) error {
	state, err := Load()
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("loading boot state: %w", err)
		}
		state = &State{StartedAt: time.Now()}
	}
	stage := Stage{Name: name, Status: status, Duration: duration, Detail: detail}
	updated := false
	for i := range state.Stages {
		if state.Stages[i].Name == name {
			state.Stages[i] = stage
			updated = true
			break
		}
	}
	if !updated {
		state.Stages = append(state.Stages, stage)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling boot state: %w", err)
	}
	return os.WriteFile(StatePath, data, 0644)
}

// Complete sets CompletedAt on the persisted state.
func Complete() error {
	state, err := Load()
	if err != nil {
		return fmt.Errorf("loading boot state: %w", err)
	}
	state.CompletedAt = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling boot state: %w", err)
	}
	return os.WriteFile(StatePath, data, 0644)
}
