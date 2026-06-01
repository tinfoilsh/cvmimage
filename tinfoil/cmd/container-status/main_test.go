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

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
)

type fakeContainerClient struct {
	inspect map[string]container.InspectResponse
	errs    map[string]error
}

func (f fakeContainerClient) ContainerInspect(_ context.Context, name string) (container.InspectResponse, error) {
	if err := f.errs[name]; err != nil {
		return container.InspectResponse{}, err
	}
	if inspect, ok := f.inspect[name]; ok {
		return inspect, nil
	}
	return container.InspectResponse{}, errdefs.ErrNotFound
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
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "declared:latest", Restart: "unless-stopped"}, container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			Name:         "/model",
			RestartCount: 2,
			State: &container.State{
				Status:    "running",
				Running:   true,
				StartedAt: "2026-01-02T03:04:05Z",
			},
			HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped}},
		},
		Config: &container.Config{Image: "actual:latest"},
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
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "model:latest"}, container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			Name:         "/model",
			RestartCount: 4,
			State: &container.State{
				Status:     "restarting",
				Restarting: true,
				ExitCode:   1,
				Error:      "restart loop",
			},
			HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyOnFailure, MaximumRetryCount: 10}},
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
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "model:latest"}, container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			State: &container.State{
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
	got := containerStatusFromInspect(declaredContainer{Name: "model", Image: "model:latest"}, container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			State: &container.State{
				Status: "running",
				Health: &container.Health{
					Status:        container.Unhealthy,
					FailingStreak: 3,
					Log: []*container.HealthcheckResult{
						{Start: start.Add(-time.Minute), End: end.Add(-time.Minute), ExitCode: 0, Output: "old"},
						{Start: start, End: end, ExitCode: 1, Output: "model still loading"},
					},
				},
			},
		},
	})

	if got.Health == nil {
		t.Fatal("expected health state")
	}
	if got.Health.Status != container.Unhealthy || got.Health.FailingStreak != 3 {
		t.Fatalf("health status/streak = %q/%d", got.Health.Status, got.Health.FailingStreak)
	}
	if got.Health.LastCheckExitCode == nil || *got.Health.LastCheckExitCode != 1 {
		t.Fatalf("last health check = %#v", got.Health)
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
		inspect: map[string]container.InspectResponse{
			"model": {
				ContainerJSONBase: &container.ContainerJSONBase{
					Name:  "/model",
					State: &container.State{Status: "running", Running: true},
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
	if got.ObservedAt.IsZero() {
		t.Fatal("expected observed_at to be set")
	}
}
