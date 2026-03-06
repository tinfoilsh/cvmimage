package boot

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const StatePath = "/mnt/ramdisk/boot-state.json"

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
}

// Write serializes the boot state to the ramdisk.
func (t *Tracker) Write() error {
	t.state.CompletedAt = time.Now()
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
