package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
)

const (
	pollInterval = 5 * time.Second
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
	ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error)
}

type containersResponse struct {
	ObservedAt  time.Time         `json:"observed_at"`
	Containers  []containerStatus `json:"containers"`
	Unavailable string            `json:"unavailable,omitempty"`
}

type containerStatus struct {
	Name          string           `json:"name"`
	ContainerID   string           `json:"container_id,omitempty"`
	Image         string           `json:"image"`
	Declared      bool             `json:"declared"`
	Created       bool             `json:"created"`
	Status        string           `json:"status,omitempty"`
	RestartCount  int              `json:"restart_count"`
	RestartPolicy string           `json:"restart_policy,omitempty"`
	OOMKilled     bool             `json:"oom_killed"`
	ExitCode      int              `json:"exit_code"`
	Error         string           `json:"error,omitempty"`
	StartedAt     string           `json:"started_at,omitempty"`
	FinishedAt    string           `json:"finished_at,omitempty"`
	Health        *containerHealth `json:"health,omitempty"`
}

type containerHealth struct {
	Status            string     `json:"status"`
	FailingStreak     int        `json:"failing_streak"`
	LastCheckStart    *time.Time `json:"last_check_start,omitempty"`
	LastCheckEnd      *time.Time `json:"last_check_end,omitempty"`
	LastCheckExitCode *int       `json:"last_check_exit_code,omitempty"`
}

func RunStatusPublisher(ctx context.Context) error {
	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	log.Printf("Starting tinfoil-containers status publisher")
	publishAndLog(ctx, cli)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			publishAndLog(ctx, cli)
		}
	}
}

func PublishStatus(ctx context.Context) error {
	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()
	return publishContainerStatus(ctx, cli, boot.RuntimeConfigPath, boot.ContainerStatusPath)
}

func publishAndLog(ctx context.Context, cli containerStatusClient) {
	if err := publishContainerStatus(ctx, cli, boot.RuntimeConfigPath, boot.ContainerStatusPath); err != nil {
		log.Printf("container status publish failed: %v", err)
	}
}

func publishContainerStatus(ctx context.Context, cli containerStatusClient, configPath, outputPath string) error {
	declared, err := loadDeclaredContainers(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("loading declared containers: %w", err)
	}

	previous, err := loadPreviousContainerStatus(outputPath)
	if err != nil {
		return fmt.Errorf("loading previous status: %w", err)
	}
	states, inspectErr := inspectDeclaredContainers(ctx, cli, declared)
	if inspectErr != nil {
		states = preservePreviousContainerStatuses(declared, previous, states)
	}
	mergeContainerLifecycles(previous, states)
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

func preservePreviousContainerStatuses(declared []declaredContainer, previous, current []containerStatus) []containerStatus {
	previousByName := make(map[string]containerStatus, len(previous))
	for _, status := range previous {
		previousByName[status.Name] = status
	}
	currentByName := make(map[string]containerStatus, len(current))
	for _, status := range current {
		currentByName[status.Name] = status
	}
	preserved := make([]containerStatus, 0, len(declared))
	for _, container := range declared {
		if status, ok := currentByName[container.Name]; ok {
			preserved = append(preserved, status)
		} else if status, ok := previousByName[container.Name]; ok {
			preserved = append(preserved, status)
		}
	}
	return preserved
}

func loadPreviousContainerStatus(path string) ([]containerStatus, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var response containersResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return response.Containers, nil
}

func mergeContainerLifecycles(previous, current []containerStatus) {
	byName := make(map[string]containerStatus, len(previous))
	for _, status := range previous {
		byName[status.Name] = status
	}
	for i := range current {
		prior, ok := byName[current[i].Name]
		if !ok || !prior.Created || !current[i].Created {
			continue
		}
		observedReplacement := prior.ContainerID != "" && current[i].ContainerID != "" && prior.ContainerID != current[i].ContainerID
		observedRestart := prior.StartedAt != "" && current[i].StartedAt != "" && prior.StartedAt != current[i].StartedAt
		if observedReplacement || observedRestart {
			current[i].RestartCount = max(current[i].RestartCount, prior.RestartCount+1)
		} else {
			current[i].RestartCount = max(current[i].RestartCount, prior.RestartCount)
		}
	}
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
	states := make([]containerStatus, 0, len(declared))
	for _, c := range declared {
		if c.Name == "" {
			continue
		}
		result, err := cli.ContainerInspect(ctx, c.Name, client.ContainerInspectOptions{})
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
		states = append(states, containerStatusFromInspect(c, result.Container))
	}
	return states, nil
}

func containerStatusFromInspect(declared declaredContainer, inspect container.InspectResponse) containerStatus {
	status := containerStatus{
		Name:          declared.Name,
		ContainerID:   inspect.ID,
		Image:         declared.Image,
		Declared:      true,
		Created:       true,
		RestartPolicy: declared.Restart,
	}

	if inspect.Config != nil && inspect.Config.Image != "" {
		status.Image = inspect.Config.Image
	}
	if inspect.Name != "" {
		status.Name = strings.TrimPrefix(inspect.Name, "/")
	}
	if inspect.HostConfig != nil && inspect.HostConfig.RestartPolicy.Name != "" {
		status.RestartPolicy = string(inspect.HostConfig.RestartPolicy.Name)
		if inspect.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
			status.RestartPolicy = fmt.Sprintf("%s:%d", status.RestartPolicy, inspect.HostConfig.RestartPolicy.MaximumRetryCount)
		}
	}
	status.RestartCount = inspect.RestartCount
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
