package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
)

const (
	pollInterval            = 5 * time.Second
	maxReportedRestartCount = 255
	processOriginal         = "original"
	processReplacement      = "replacement"
)

type declaredContainer struct {
	Name    string `yaml:"name"`
	Image   string `yaml:"image"`
	Restart string `yaml:"restart"`
}

type declaredConfig struct {
	Containers []declaredContainer `yaml:"containers"`
}

type containerStatusClient interface {
	ContainerInspect(context.Context, string) (container.InspectResponse, error)
}

type containersResponse struct {
	ObservedAt  time.Time         `json:"observed_at"`
	Containers  []containerStatus `json:"containers"`
	Unavailable string            `json:"unavailable,omitempty"`
}

type containerStatus struct {
	Name                  string           `json:"name"`
	Image                 string           `json:"image"`
	Declared              bool             `json:"declared"`
	Created               bool             `json:"created"`
	ContainerID           string           `json:"container_id,omitempty"`
	Process               string           `json:"process,omitempty"`
	LifecycleComplete     bool             `json:"lifecycle_complete"`
	Status                string           `json:"status,omitempty"`
	RestartCount          int              `json:"restart_count"`
	RestartCountTruncated bool             `json:"restart_count_truncated"`
	RestartPolicy         string           `json:"restart_policy,omitempty"`
	LatestOutcome         *processOutcome  `json:"latest_outcome,omitempty"`
	OOMKilled             bool             `json:"oom_killed"`
	ExitCode              int              `json:"exit_code"`
	Error                 string           `json:"error,omitempty"`
	StartedAt             string           `json:"started_at,omitempty"`
	FinishedAt            string           `json:"finished_at,omitempty"`
	Health                *containerHealth `json:"health,omitempty"`
}

type processOutcome struct {
	Process    string `json:"process"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	OOMKilled  bool   `json:"oom_killed"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type containerHealth struct {
	Status            string     `json:"status"`
	FailingStreak     int        `json:"failing_streak"`
	LastCheckStart    *time.Time `json:"last_check_start,omitempty"`
	LastCheckEnd      *time.Time `json:"last_check_end,omitempty"`
	LastCheckExitCode *int       `json:"last_check_exit_code,omitempty"`
}

func main() {
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("creating docker client: %v", err)
	}
	defer cli.Close()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	log.Printf("Starting tinfoil container-status publisher")
	publishAndLog(ctx, cli)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publishAndLog(ctx, cli)
		}
	}
}

func publishAndLog(ctx context.Context, cli containerStatusClient) {
	if err := publishContainerStatus(ctx, cli, boot.ConfigPath, boot.ContainerStatusPath); err != nil {
		log.Printf("container status publish failed: %v", err)
	}
}

func publishContainerStatus(ctx context.Context, cli containerStatusClient, configPath, outputPath string) error {
	previous, persistedValid := loadPreviousStatuses(outputPath)
	declared, err := loadDeclaredContainers(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("loading declared containers: %w", err)
	}

	states, inspectErr := inspectDeclaredContainersWithPrevious(ctx, cli, declared, previous, persistedValid)
	resp := containersResponse{
		ObservedAt: time.Now().UTC(),
		Containers: states,
	}
	if inspectErr != nil {
		resp.Unavailable = inspectErr.Error()
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling status: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("writing status: %w", err)
	}
	return inspectErr
}

func loadDeclaredContainers(path string) ([]declaredContainer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg declaredConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.Containers, nil
}

func inspectDeclaredContainers(ctx context.Context, cli containerStatusClient, declared []declaredContainer) ([]containerStatus, error) {
	return inspectDeclaredContainersWithPrevious(ctx, cli, declared, nil, true)
}

func inspectDeclaredContainersWithPrevious(ctx context.Context, cli containerStatusClient, declared []declaredContainer, previous map[string]containerStatus, persistedValid bool) ([]containerStatus, error) {
	states := make([]containerStatus, 0, len(declared))
	for _, c := range declared {
		if c.Name == "" {
			continue
		}
		inspect, err := cli.ContainerInspect(ctx, c.Name)
		if err != nil {
			if errdefs.IsNotFound(err) {
				states = append(states, containerStatus{
					Name:          c.Name,
					Image:         c.Image,
					Declared:      true,
					Created:       false,
					RestartPolicy: c.Restart,
					Error:         "container not found",
				})
				continue
			}
			return states, fmt.Errorf("inspecting %s: %w", c.Name, err)
		}
		status := containerStatusFromInspect(c, inspect)
		prior, found := previous[c.Name]
		applyLifecycle(&status, inspect, prior, found, persistedValid)
		states = append(states, status)
	}
	return states, nil
}

func containerStatusFromInspect(declared declaredContainer, inspect container.InspectResponse) containerStatus {
	status := containerStatus{
		Name:          declared.Name,
		Image:         declared.Image,
		Declared:      true,
		Created:       true,
		RestartPolicy: declared.Restart,
	}

	if inspect.Config != nil && inspect.Config.Image != "" {
		status.Image = inspect.Config.Image
	}
	if inspect.ContainerJSONBase == nil {
		return status
	}
	status.ContainerID = inspect.ID

	if inspect.Name != "" {
		status.Name = strings.TrimPrefix(inspect.Name, "/")
	}
	if inspect.HostConfig != nil && inspect.HostConfig.RestartPolicy.Name != "" {
		status.RestartPolicy = string(inspect.HostConfig.RestartPolicy.Name)
		if inspect.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
			status.RestartPolicy = fmt.Sprintf("%s:%d", status.RestartPolicy, inspect.HostConfig.RestartPolicy.MaximumRetryCount)
		}
	}
	status.RestartCount, status.RestartCountTruncated, _ = boundedRestartCount(inspect.RestartCount)
	if inspect.State == nil {
		return status
	}

	status.Status = string(inspect.State.Status)
	status.OOMKilled = inspect.State.OOMKilled
	status.ExitCode = inspect.State.ExitCode
	status.Error = inspect.State.Error
	status.StartedAt = inspect.State.StartedAt
	status.FinishedAt = inspect.State.FinishedAt
	status.Health = containerHealthFromDocker(inspect.State.Health)

	return status
}

func applyLifecycle(status *containerStatus, inspect container.InspectResponse, prior containerStatus, found, persistedValid bool) {
	restartCount, truncated, countValid := boundedRestartCount(inspect.RestartCount)
	status.RestartCount = restartCount
	status.RestartCountTruncated = truncated
	status.Process = processForRestartCount(restartCount)
	status.LifecycleComplete = persistedValid && countValid && !truncated && inspect.RestartCount == 0 && validContainerID(status.ContainerID)

	if found && prior.Created && (!validPriorStatus(prior) || prior.ContainerID != status.ContainerID) {
		status.LifecycleComplete = false
	} else if found && prior.Created {
		if prior.Process == processReplacement {
			status.Process = processReplacement
		}
		sameStart := prior.StartedAt == status.StartedAt
		if prior.StartedAt != "" && status.StartedAt != "" && !sameStart {
			status.Process = processReplacement
		}
		initialStart := prior.StartedAt == "" && status.StartedAt != "" && prior.Status == string(container.StateCreated)
		priorTerminal := terminalStatus(prior.Status) && prior.LatestOutcome != nil
		transitionProven := false
		switch {
		case truncated || prior.RestartCountTruncated:
		case restartCount == prior.RestartCount && (sameStart || initialStart):
			transitionProven = true
		case restartCount == prior.RestartCount && priorTerminal:
			status.Process = processReplacement
			transitionProven = true
		case restartCount == prior.RestartCount+1 && terminalStatus(status.Status):
			status.Process = processReplacement
			transitionProven = true
		case restartCount < prior.RestartCount && priorTerminal && !sameStart:
			status.Process = processReplacement
			transitionProven = true
		}
		status.LifecycleComplete = persistedValid && countValid && prior.LifecycleComplete && transitionProven
		if transitionProven {
			status.LatestOutcome = cloneOutcome(prior.LatestOutcome)
		}
	}

	outcomeProcess := status.Process
	priorReplacement := found && prior.Created && validPriorStatus(prior) && prior.ContainerID == status.ContainerID && prior.Process == processReplacement
	if inspect.State != nil && inspect.State.Status == container.StateRestarting && inspect.RestartCount == 1 && !priorReplacement {
		outcomeProcess = processOriginal
	}
	if outcome := outcomeFromInspect(inspect.State, outcomeProcess); outcome != nil {
		status.LatestOutcome = outcome
	}
}

func loadPreviousStatuses(path string) (map[string]containerStatus, bool) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, true
	}
	if err != nil {
		return nil, false
	}
	var response containersResponse
	if json.Unmarshal(data, &response) != nil || response.ObservedAt.IsZero() {
		return nil, false
	}
	previous := make(map[string]containerStatus, len(response.Containers))
	for _, status := range response.Containers {
		if status.Name == "" {
			return nil, false
		}
		if !status.Created && (status.ContainerID != "" || status.Process != "" || status.LifecycleComplete || status.LatestOutcome != nil) {
			return nil, false
		}
		if status.Created && !validPriorStatus(status) {
			return nil, false
		}
		if _, exists := previous[status.Name]; exists {
			return nil, false
		}
		previous[status.Name] = status
	}
	return previous, true
}

func validPriorStatus(status containerStatus) bool {
	if !validContainerID(status.ContainerID) || status.RestartCount < 0 || status.RestartCount > maxReportedRestartCount {
		return false
	}
	if status.Process != processOriginal && status.Process != processReplacement {
		return false
	}
	if status.RestartCount > 0 && status.Process != processReplacement {
		return false
	}
	if status.StartedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, status.StartedAt); err != nil {
			return false
		}
	}
	if status.LatestOutcome == nil {
		return true
	}
	outcome := status.LatestOutcome
	return terminalStatus(outcome.Status) && outcome.ExitCode >= 0 && outcome.ExitCode <= 255 &&
		(outcome.Process == processOriginal || outcome.Process == processReplacement)
}

func validContainerID(containerID string) bool {
	if len(containerID) != 64 {
		return false
	}
	_, err := hex.DecodeString(containerID)
	return err == nil
}

func outcomeFromInspect(state *container.State, process string) *processOutcome {
	if state == nil || !terminalStatus(string(state.Status)) || state.ExitCode < 0 || state.ExitCode > 255 {
		return nil
	}
	return &processOutcome{
		Process:    process,
		Status:     string(state.Status),
		ExitCode:   state.ExitCode,
		OOMKilled:  state.OOMKilled,
		FinishedAt: state.FinishedAt,
	}
}

func terminalStatus(status string) bool {
	return status == string(container.StateExited) || status == string(container.StateDead) || status == string(container.StateRestarting)
}

func processForRestartCount(restartCount int) string {
	if restartCount == 0 {
		return processOriginal
	}
	return processReplacement
}

func boundedRestartCount(restartCount int) (int, bool, bool) {
	if restartCount < 0 {
		return 0, false, false
	}
	if restartCount > maxReportedRestartCount {
		return maxReportedRestartCount, true, true
	}
	return restartCount, false, true
}

func cloneOutcome(outcome *processOutcome) *processOutcome {
	if outcome == nil {
		return nil
	}
	copy := *outcome
	return &copy
}

func containerHealthFromDocker(health *container.Health) *containerHealth {
	if health == nil {
		return nil
	}
	out := &containerHealth{
		Status:        string(health.Status),
		FailingStreak: health.FailingStreak,
	}
	if len(health.Log) == 0 {
		return out
	}
	last := health.Log[len(health.Log)-1]
	if last == nil {
		return out
	}
	out.LastCheckStart = &last.Start
	out.LastCheckEnd = &last.End
	out.LastCheckExitCode = &last.ExitCode
	return out
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
