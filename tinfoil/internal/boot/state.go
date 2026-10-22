package boot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	failureStageLimit  = 64
	failureDetailLimit = 512
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
	StageConfig           = "config"
	StageNetwork          = "network"
	StageIdentity         = "identity"
	StageCPUAttestation   = "cpu-attestation"
	StageGPUAttestation   = "gpu-attestation"
	StageKeyserverSecrets = "keyserver-secrets"
	StageCertificate      = "certificate"
	StageRegistryAuth     = "registry-auth"
	StageModels           = "models"
	StageVolumes          = "volumes"
	StageFirewall         = "firewall"
	StageContainers       = "containers"
	StageShim             = "shim"
)

// InitialStages is the ordered list of stages known at boot time.
// Both boot and shim use this as the starting point.
var InitialStages = []string{
	StageConfig, StageNetwork, StageIdentity, StageCPUAttestation, StageGPUAttestation, StageCertificate,
	StageKeyserverSecrets, StageRegistryAuth, StageFirewall, StageModels, StageVolumes, StageContainers, StageShim,
}

// Tracker records boot stages as they complete.
type Tracker struct {
	mu    sync.Mutex
	state State
}

// writeStateAtomic writes data to path via a temp file in the same directory
// + rename so concurrent readers never observe a partial file.
func writeStateAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating boot state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "boot-state-*.json")
	if err != nil {
		return fmt.Errorf("creating temp boot state: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing temp boot state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp boot state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming boot state: %w", err)
	}
	return nil
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

// ResumeTracker loads the current boot state so another process can continue
// recording stages without discarding work already completed by tinfoil-boot.
func ResumeTracker() (*Tracker, error) {
	data, err := os.ReadFile(StatePath)
	if err != nil {
		return nil, fmt.Errorf("reading boot state: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing boot state: %w", err)
	}
	return &Tracker{state: state}, nil
}

// Record updates an existing stage by name or appends a new one. Auto-flushes.
func (t *Tracker) Record(name, status string, duration time.Duration, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
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
	if err := t.flushLocked(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to flush boot state: %v\n", err)
	}
}

// RecordSubstages sets the substages on an existing stage and flushes.
func (t *Tracker) RecordSubstages(name string, substages []Stage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.state.Stages {
		if t.state.Stages[i].Name == name {
			t.state.Stages[i].Stages = substages
			break
		}
	}
	if err := t.flushLocked(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to flush boot state: %v\n", err)
	}
}

func (t *Tracker) flushLocked() error {
	return persistState(StatePath, &t.state)
}

// persistState writes state to path atomically.
func persistState(path string, state *State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling boot state: %w", err)
	}
	return writeStateAtomic(path, data)
}

// Load reads the boot state from the ramdisk.
func Load() (*State, error) {
	return loadState(StatePath)
}

func loadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing boot state: %w", err)
	}
	return &state, nil
}

// CompleteFailure seals a recorded boot failure after every state writer has
// stopped. The status-only shim then serves the state read-only, and every
// other writer refuses sealed states.
func CompleteFailure() error {
	return completeFailure(StatePath)
}

func completeFailure(path string) error {
	state, err := loadState(path)
	if err != nil {
		return err
	}
	if !state.HasFailed() {
		return fmt.Errorf("no failed boot stage recorded")
	}
	skipPending(state.Stages)
	if state.CompletedAt.IsZero() {
		state.CompletedAt = time.Now()
	}
	return persistState(path, state)
}

func skipPending(stages []Stage) {
	for i := range stages {
		if stages[i].Status == StatusPending {
			stages[i].Status = StatusSkipped
			stages[i].Detail = "not run because boot failed"
		}
		skipPending(stages[i].Stages)
	}
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

// FailureSummary returns the first failed fixed boot stage as bounded,
// log-safe text. It is diagnostic only and must not replace readiness checks.
func (s *State) FailureSummary() (string, bool) {
	if len(s.Stages) != len(InitialStages) {
		return "", false
	}
	for index, name := range InitialStages {
		if s.Stages[index].Name != name {
			return "", false
		}
	}
	for _, stage := range s.Stages {
		if stage.Status != StatusFailed {
			continue
		}
		name := boundedStateText(stage.Name, failureStageLimit)
		if name == "" {
			return "", false
		}
		summary := "boot stage " + strconv.Quote(name) + " failed"
		if detail := boundedStateText(stage.Detail, failureDetailLimit); detail != "" {
			summary += ": " + strconv.Quote(detail)
		}
		return summary, true
	}
	return "", false
}

func boundedStateText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	end := 0
	for end < len(value) {
		_, size := utf8.DecodeRuneInString(value[end:])
		if end+size > limit {
			break
		}
		end += size
	}
	return value[:end] + "..."
}

// IsSealed reports whether the state is terminal: completed with a recorded
// failure. Sealed states are immutable; every writer must refuse to alter one.
func (s *State) IsSealed() bool {
	return !s.CompletedAt.IsZero() && s.HasFailed()
}

// RecordStage loads the current state from disk, updates or appends a stage,
// and writes it back. Safe to call from a separate process after boot has exited.
func RecordStage(name, status string, duration time.Duration, detail string) error {
	return recordStage(StatePath, name, status, duration, detail)
}

func recordStage(path, name, status string, duration time.Duration, detail string) error {
	state, err := loadState(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("loading boot state: %w", err)
		}
		state = &State{StartedAt: time.Now()}
	}
	if state.IsSealed() {
		return fmt.Errorf("boot state is sealed: refusing to record stage %q", name)
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
	return persistState(path, state)
}

// Complete sets CompletedAt on the persisted state.
func Complete() error {
	return complete(StatePath)
}

func complete(path string) error {
	state, err := loadState(path)
	if err != nil {
		return fmt.Errorf("loading boot state: %w", err)
	}
	if state.IsSealed() {
		return errors.New("boot state is sealed: refusing to complete")
	}
	state.CompletedAt = time.Now()
	return persistState(path, state)
}
