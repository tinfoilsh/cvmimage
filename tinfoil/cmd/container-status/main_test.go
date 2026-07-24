package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeContainerClient struct {
	inspect map[string]containerInspect
	errs    map[string]error
}

func lifecycleStatus(inspect containerInspect, prior containerStatus, found, persistedValid bool) containerStatus {
	status := containerStatusFromInspect(declaredContainer{Name: "model", Image: "model:latest"}, inspect)
	applyLifecycle(&status, inspect, prior, found, persistedValid)
	return status
}

func (f fakeContainerClient) ContainerInspect(_ context.Context, name string) (containerInspect, error) {
	if err := f.errs[name]; err != nil {
		return containerInspect{}, err
	}
	if inspect, ok := f.inspect[name]; ok {
		return inspect, nil
	}
	return containerInspect{}, errContainerNotFound
}

func TestInspectDeclaredContainers_MissingContainer(t *testing.T) {
	states, err := inspectDeclaredContainers(context.Background(), fakeContainerClient{}, []declaredContainer{{
		Name:    "model",
		Image:   "example/model:latest",
		Restart: "always",
	}})
	if err != nil {
		t.Fatalf("inspectDeclaredContainers returned error: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("got %d states, want 1", len(states))
	}
	got := states[0]
	if !got.Declared || got.Created {
		t.Fatalf("missing container declared/created = %v/%v, want true/false", got.Declared, got.Created)
	}
	if got.Error != "container not found" {
		t.Fatalf("missing container error = %q", got.Error)
	}
	if got.RestartPolicy != "always" {
		t.Fatalf("restart policy = %q, want always", got.RestartPolicy)
	}
}

func TestContainerStatusFromInspect_RunningContainer(t *testing.T) {
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "declared:latest", Restart: "unless-stopped"}, containerInspect{
		Base: &containerInspectBase{
			Name:         "/model",
			RestartCount: 2,
			State: &containerState{
				Status:    "running",
				StartedAt: "2026-01-02T03:04:05Z",
			},
			HostConfig: &containerHostConfig{RestartPolicy: containerRestartPolicy{Name: "unless-stopped"}},
		},
		Config: &containerConfig{Image: "actual:latest"},
	})

	if got.Name != "model" || got.Image != "actual:latest" {
		t.Fatalf("name/image = %q/%q", got.Name, got.Image)
	}
	if !got.Created || got.Status != "running" {
		t.Fatalf("created/status = %v/%q", got.Created, got.Status)
	}
	if got.RestartCount != 2 || got.RestartPolicy != "unless-stopped" {
		t.Fatalf("restart count/policy = %d/%q", got.RestartCount, got.RestartPolicy)
	}
	if got.StartedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("started_at = %q", got.StartedAt)
	}
}

func TestContainerStatusFromInspect_RestartingContainer(t *testing.T) {
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "model:latest"}, containerInspect{
		Base: &containerInspectBase{
			Name:         "/model",
			RestartCount: 4,
			State: &containerState{
				Status:   "restarting",
				ExitCode: 1,
				Error:    "restart loop",
			},
			HostConfig: &containerHostConfig{RestartPolicy: containerRestartPolicy{Name: "on-failure", MaximumRetryCount: 10}},
		},
	})

	if got.Status != "restarting" || got.RestartCount != 4 {
		t.Fatalf("status/restart_count = %q/%d", got.Status, got.RestartCount)
	}
	if got.RestartPolicy != "on-failure:10" {
		t.Fatalf("restart policy = %q", got.RestartPolicy)
	}
	if got.ExitCode != 1 || got.Error != "restart loop" {
		t.Fatalf("exit/error = %d/%q", got.ExitCode, got.Error)
	}
}

func TestContainerStatusFromInspect_OOMKilledExitedContainer(t *testing.T) {
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "model:latest"}, containerInspect{
		Base: &containerInspectBase{
			State: &containerState{
				Status:     "exited",
				OOMKilled:  true,
				ExitCode:   137,
				FinishedAt: "2026-01-02T03:05:05Z",
			},
		},
	})

	if !got.OOMKilled || got.ExitCode != 137 || got.Status != "exited" {
		t.Fatalf("oom/exit/status = %v/%d/%q", got.OOMKilled, got.ExitCode, got.Status)
	}
	if got.FinishedAt == "" {
		t.Fatal("expected finished_at to be set")
	}
}

func TestContainerStatusFromInspect_UnhealthyHealthcheck(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	end := start.Add(time.Second)
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "model:latest"}, containerInspect{
		Base: &containerInspectBase{
			State: &containerState{
				Status: "running",
				Health: &containerHealthState{
					Status:        "unhealthy",
					FailingStreak: 3,
					Log: []*containerHealthResult{
						{Start: start.Add(-time.Minute), End: end.Add(-time.Minute), ExitCode: 0},
						{Start: start, End: end, ExitCode: 1},
					},
				},
			},
		},
	})

	if got.Health == nil {
		t.Fatal("expected health state")
	}
	if got.Health.Status != "unhealthy" || got.Health.FailingStreak != 3 {
		t.Fatalf("health status/streak = %q/%d", got.Health.Status, got.Health.FailingStreak)
	}
	if got.Health.LastCheckExitCode == nil || *got.Health.LastCheckExitCode != 1 {
		t.Fatalf("last health check = %#v", got.Health)
	}
}

func TestLifecycleFreshBaselineAndInvalidPersistence(t *testing.T) {
	inspect := containerInspect{
		Base: &containerInspectBase{
			ID: strings.Repeat("0", 64),
			State: &containerState{
				Status:    containerStateRunning,
				StartedAt: "2026-07-24T00:30:00Z",
			},
		},
	}

	fresh := lifecycleStatus(inspect, containerStatus{}, false, true)
	if !fresh.LifecycleComplete || fresh.Process != processOriginal {
		t.Fatalf("fresh lifecycle baseline = %#v", fresh)
	}

	invalid := lifecycleStatus(inspect, containerStatus{}, false, false)
	if invalid.LifecycleComplete {
		t.Fatalf("invalid persisted lifecycle = %#v", invalid)
	}
}

func TestLifecycleMissingStateFailsClosed(t *testing.T) {
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{ID: strings.Repeat("1", 64)},
	}, containerStatus{}, false, true)

	if got.LifecycleComplete || got.Process != "" {
		t.Fatalf("missing state lifecycle = %#v", got)
	}
}

func TestLifecycleDisappearanceCannotResetContinuity(t *testing.T) {
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID: strings.Repeat("2", 64),
			State: &containerState{
				Status:    containerStateRunning,
				StartedAt: "2026-07-24T00:45:00Z",
			},
		},
	}, containerStatus{
		Name:    "model",
		Created: false,
	}, true, true)

	if got.LifecycleComplete {
		t.Fatalf("recreated lifecycle = %#v", got)
	}
}

func TestLifecycleManualRestartBetweenInspectsFailsClosed(t *testing.T) {
	prior := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       strings.Repeat("a", 64),
		Process:           processOriginal,
		LifecycleComplete: true,
		Status:            "running",
		StartedAt:         "2026-07-24T01:00:00Z",
	}
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID:           prior.ContainerID,
			RestartCount: 1,
			State: &containerState{
				Status:    "running",
				StartedAt: "2026-07-24T01:01:00Z",
			},
		},
	}, prior, true, true)

	if got.Process != processReplacement || got.RestartCount != 1 || got.LifecycleComplete {
		t.Fatalf("manual restart lifecycle = %#v", got)
	}
	if got.LatestOutcome != nil {
		t.Fatalf("missed manual restart reported outcome %#v", got.LatestOutcome)
	}
}

func TestLifecycleMissedSameCountTransitionFailsClosed(t *testing.T) {
	prior := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       strings.Repeat("b", 64),
		Process:           processOriginal,
		LifecycleComplete: true,
		Status:            "running",
		StartedAt:         "2026-07-24T02:00:00Z",
	}
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID: prior.ContainerID,
			State: &containerState{
				Status:    "running",
				StartedAt: "2026-07-24T02:01:00Z",
			},
		},
	}, prior, true, true)

	if got.Process != processReplacement || got.RestartCount != 0 || got.LifecycleComplete {
		t.Fatalf("missed same-count transition = %#v", got)
	}
}

func TestLifecycleObservedCleanStopThenStartRemainsComplete(t *testing.T) {
	containerID := strings.Repeat("c", 64)
	running := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       containerID,
		Process:           processOriginal,
		LifecycleComplete: true,
		Status:            "running",
		StartedAt:         "2026-07-24T03:00:00Z",
	}
	stopped := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID: containerID,
			State: &containerState{
				Status:     "exited",
				ExitCode:   0,
				StartedAt:  running.StartedAt,
				FinishedAt: "2026-07-24T03:01:00Z",
			},
		},
	}, running, true, true)
	if !stopped.LifecycleComplete || stopped.LatestOutcome == nil || stopped.LatestOutcome.Process != processOriginal {
		t.Fatalf("observed clean stop = %#v", stopped)
	}

	restarted := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID: containerID,
			State: &containerState{
				Status:    "running",
				StartedAt: "2026-07-24T03:02:00Z",
			},
		},
	}, stopped, true, true)
	if restarted.Process != processReplacement || restarted.RestartCount != 0 || !restarted.LifecycleComplete {
		t.Fatalf("observed clean start = %#v", restarted)
	}
	if restarted.LatestOutcome == nil || restarted.LatestOutcome.ExitCode != 0 {
		t.Fatalf("clean start lost latest outcome: %#v", restarted.LatestOutcome)
	}
}

func TestLifecycleRestartingInspectCapturesLatestOutcome(t *testing.T) {
	prior := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       strings.Repeat("d", 64),
		Process:           processOriginal,
		LifecycleComplete: true,
		Status:            "running",
		StartedAt:         "2026-07-24T04:00:00Z",
	}
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID:           prior.ContainerID,
			RestartCount: 1,
			State: &containerState{
				Status:     "restarting",
				ExitCode:   9,
				StartedAt:  prior.StartedAt,
				FinishedAt: "2026-07-24T04:01:00Z",
			},
		},
	}, prior, true, true)

	if got.Process != processReplacement || !got.LifecycleComplete || got.LatestOutcome == nil {
		t.Fatalf("restarting lifecycle = %#v", got)
	}
	if got.LatestOutcome.Process != processOriginal || got.LatestOutcome.ExitCode != 9 {
		t.Fatalf("restarting outcome = %#v", got.LatestOutcome)
	}
}

func TestLifecycleMissedCrashLoopFailsClosed(t *testing.T) {
	prior := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       strings.Repeat("7", 64),
		Process:           processReplacement,
		LifecycleComplete: true,
		Status:            "restarting",
		RestartCount:      1,
		StartedAt:         "2026-07-24T04:30:00Z",
		LatestOutcome: &processOutcome{
			Process:    processOriginal,
			Status:     "restarting",
			ExitCode:   1,
			FinishedAt: "2026-07-24T04:31:00Z",
		},
	}
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID:           prior.ContainerID,
			RestartCount: 2,
			State:        &containerState{Status: "running", StartedAt: "2026-07-24T04:32:00Z"},
		},
	}, prior, true, true)

	if got.LifecycleComplete || got.LatestOutcome != nil || got.RestartCount != 2 {
		t.Fatalf("missed crash loop = %#v", got)
	}
}

func TestLifecycleRestartCountDecreaseFailsClosed(t *testing.T) {
	prior := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       strings.Repeat("8", 64),
		Process:           processReplacement,
		LifecycleComplete: true,
		Status:            containerStateExited,
		RestartCount:      2,
		StartedAt:         "2026-07-24T04:40:00Z",
		LatestOutcome: &processOutcome{
			Process:    processReplacement,
			Status:     containerStateExited,
			ExitCode:   1,
			FinishedAt: "2026-07-24T04:41:00Z",
		},
	}
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID:           prior.ContainerID,
			RestartCount: 1,
			State: &containerState{
				Status:    containerStateRunning,
				StartedAt: "2026-07-24T04:42:00Z",
			},
		},
	}, prior, true, true)

	if got.LifecycleComplete || got.RestartCount != 1 {
		t.Fatalf("decreased restart count lifecycle = %#v", got)
	}
}

func TestLifecycleIdentityChangeFailsClosed(t *testing.T) {
	prior := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       strings.Repeat("e", 64),
		Process:           processOriginal,
		LifecycleComplete: true,
		Status:            "running",
		StartedAt:         "2026-07-24T05:00:00Z",
	}
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID:    strings.Repeat("f", 64),
			State: &containerState{Status: containerStateRunning, StartedAt: "2026-07-24T05:01:00Z"},
		},
	}, prior, true, true)

	if got.LifecycleComplete || got.RestartCountTruncated || got.RestartCount != 0 {
		t.Fatalf("identity change lifecycle = %#v", got)
	}
}

func TestLifecycleRestartCountTruncationFailsClosed(t *testing.T) {
	containerID := strings.Repeat("6", 64)
	prior := containerStatus{
		Name:              "model",
		Created:           true,
		ContainerID:       containerID,
		Process:           processReplacement,
		LifecycleComplete: true,
		Status:            containerStateRunning,
		RestartCount:      maxReportedRestartCount,
		StartedAt:         "2026-07-24T05:10:00Z",
	}
	got := lifecycleStatus(containerInspect{
		Base: &containerInspectBase{
			ID:           containerID,
			RestartCount: maxReportedRestartCount + 1,
			State:        &containerState{Status: containerStateRunning, StartedAt: prior.StartedAt},
		},
	}, prior, true, true)

	if got.LifecycleComplete || !got.RestartCountTruncated || got.RestartCount != maxReportedRestartCount {
		t.Fatalf("restart count truncation lifecycle = %#v", got)
	}
}

func TestLoadPreviousStatusesRejectsMalformedIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "container-status.json")
	if err := os.WriteFile(path, []byte(`{
  "observed_at": "2026-07-24T06:00:00Z",
  "containers": [{
    "name": "model",
    "created": true,
    "container_id": "invalid",
    "process": "original",
    "restart_count": 0
  }]
}`), 0o644); err != nil {
		t.Fatalf("writing previous status: %v", err)
	}
	if previous, valid := loadPreviousStatuses(path); valid || previous != nil {
		t.Fatalf("malformed previous status accepted: valid=%v previous=%#v", valid, previous)
	}
}

func TestLoadPreviousStatusesRejectsInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "container-status.json")
	if err := os.WriteFile(path, []byte(`{
  "observed_at": "2026-07-24T06:02:00Z",
  "containers": [{
    "name": "model",
    "created": true,
    "container_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "process": "original",
    "status": "unknown",
    "restart_count": 0
  }]
}`), 0o644); err != nil {
		t.Fatalf("writing previous status: %v", err)
	}
	if previous, valid := loadPreviousStatuses(path); valid || previous != nil {
		t.Fatalf("invalid state accepted: valid=%v previous=%#v", valid, previous)
	}
}

func TestLoadPreviousStatusesRejectsUnavailableObservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "container-status.json")
	if err := os.WriteFile(path, []byte(`{
  "observed_at": "2026-07-24T06:05:00Z",
  "containers": [],
  "unavailable": "inspecting model: temporary failure"
}`), 0o644); err != nil {
		t.Fatalf("writing previous status: %v", err)
	}
	if previous, valid := loadPreviousStatuses(path); valid || previous != nil {
		t.Fatalf("unavailable previous status accepted: valid=%v previous=%#v", valid, previous)
	}
}

func TestInspectDeclaredContainers_UnexpectedError(t *testing.T) {
	boom := errors.New("docker unavailable")
	states, err := inspectDeclaredContainers(context.Background(), fakeContainerClient{
		errs: map[string]error{"model": boom},
	}, []declaredContainer{{Name: "model"}})
	if err == nil || !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("expected docker error, got %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("expected no states before first inspect failure, got %#v", states)
	}
}

func TestPublishContainerStatusWritesJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	outputPath := filepath.Join(dir, "container-status.json")
	if err := os.WriteFile(configPath, []byte(`containers:
  - name: model
    image: declared:latest
    restart: always
`), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	err := publishContainerStatus(context.Background(), fakeContainerClient{
		inspect: map[string]containerInspect{
			"model": {
				Base: &containerInspectBase{
					ID:   strings.Repeat("9", 64),
					Name: "/model",
					State: &containerState{
						Status:    "running",
						StartedAt: "2026-07-24T07:00:00Z",
					},
				},
			},
		},
	}, configPath, outputPath)
	if err != nil {
		t.Fatalf("publishContainerStatus returned error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	var got containersResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshaling output: %v", err)
	}
	if len(got.Containers) != 1 || got.Containers[0].Name != "model" || got.Containers[0].Status != "running" {
		t.Fatalf("unexpected output: %#v", got)
	}
	if got.Containers[0].Process != processOriginal || !got.Containers[0].LifecycleComplete {
		t.Fatalf("unexpected lifecycle output: %#v", got.Containers[0])
	}
	if got.ObservedAt.IsZero() {
		t.Fatal("expected observed_at to be set")
	}
}
