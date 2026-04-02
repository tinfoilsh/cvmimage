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
}

const (
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusWarning = "warning"
	StatusFailed  = "failed"
)

// Tracker records boot stages as they complete.
type Tracker struct {
	state State
}

func NewTracker() *Tracker {
	return &Tracker{
		state: State{StartedAt: time.Now()},
	}
}

func (t *Tracker) Record(name, status string, duration time.Duration, detail string) {
	t.state.Stages = append(t.state.Stages, Stage{
		Name:     name,
		Status:   status,
		Duration: duration,
		Detail:   detail,
	})
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

// Write sets CompletedAt and serializes the final boot state to the ramdisk.
func (t *Tracker) Write() error {
	t.state.CompletedAt = time.Now()
	return t.Flush()
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

// HasFailed returns true if any stage has a "failed" status.
func (s *State) HasFailed() bool {
	for _, stage := range s.Stages {
		if stage.Status == StatusFailed {
			return true
		}
	}
	return false
}

// AppendStage loads the current state from disk, appends a stage, and writes
// it back. Safe to call from a separate process after boot has exited.
func AppendStage(name, status string, duration time.Duration, detail string) error {
	state, err := Load()
	if err != nil {
		state = &State{StartedAt: time.Now()}
	}
	state.Stages = append(state.Stages, Stage{
		Name:     name,
		Status:   status,
		Duration: duration,
		Detail:   detail,
	})
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling boot state: %w", err)
	}
	return os.WriteFile(StatePath, data, 0644)
}
