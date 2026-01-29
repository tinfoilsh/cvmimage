package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-units"
)

// launchContainers starts all containers from the config
func launchContainers(config *Config) error {
	if len(config.Containers) == 0 {
		slog.Info("no containers to launch")
		return nil
	}

	// Load external config once for env/secrets expansion
	extConfig, _ := getExternalConfig() // nil is fine, we'll warn per-key

	slog.Info("launching containers", "count", len(config.Containers))
	for _, c := range config.Containers {
		if err := startContainer(c, extConfig); err != nil {
			return fmt.Errorf("starting container %s: %w", c.Name, err)
		}
	}
	return nil
}

// startContainer starts a Docker container using the Docker SDK
func startContainer(c Container, extConfig *ExternalConfig) error {
	if !containerNamePattern.MatchString(c.Name) {
		return fmt.Errorf("invalid container name: %s", c.Name)
	}
	if c.Image == "" {
		return fmt.Errorf("no image specified for container %s", c.Name)
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	// Build environment variables
	env := buildEnv(c.Env, c.Secrets, extConfig)

	// Container configuration
	containerConfig := &container.Config{
		Image:       c.Image,
		Env:         env,
		Cmd:         c.Command,
		Entrypoint:  c.Entrypoint,
		WorkingDir:  c.WorkingDir,
		User:        c.User,
		StopSignal:  c.StopSignal,
		StopTimeout: c.StopTimeout,
	}

	// Healthcheck
	if c.Healthcheck != nil {
		containerConfig.Healthcheck = &container.HealthConfig{
			Test:        c.Healthcheck.Test,
			Interval:    parseDuration(c.Healthcheck.Interval),
			Timeout:     parseDuration(c.Healthcheck.Timeout),
			Retries:     c.Healthcheck.Retries,
			StartPeriod: parseDuration(c.Healthcheck.StartPeriod),
		}
	}

	// Host configuration
	hostConfig := &container.HostConfig{
		NetworkMode:    "host",
		Runtime:        c.Runtime,
		IpcMode:        container.IpcMode(c.IPC),
		CapAdd:         c.CapAdd,
		CapDrop:        c.CapDrop,
		SecurityOpt:    c.SecurityOpt,
		ReadonlyRootfs: c.ReadOnly,
		Tmpfs:          c.Tmpfs,
		Binds:          []string{ramdiskPath + ":/tinfoil"},
	}

	// Restart policy
	if c.Restart != "" {
		hostConfig.RestartPolicy = container.RestartPolicy{Name: container.RestartPolicyMode(c.Restart)}
	}

	// Resource limits
	if c.ShmSize != "" {
		if size, err := units.RAMInBytes(c.ShmSize); err == nil {
			hostConfig.ShmSize = size
		}
	}
	if c.Memory != "" {
		if mem, err := units.RAMInBytes(c.Memory); err == nil {
			hostConfig.Resources.Memory = mem
		}
	}
	if c.CPUs > 0 {
		hostConfig.Resources.NanoCPUs = int64(c.CPUs * 1e9)
	}

	// Devices
	for _, dev := range c.Devices {
		hostConfig.Devices = append(hostConfig.Devices, container.DeviceMapping{
			PathOnHost: dev, PathInContainer: dev, CgroupPermissions: "rwm",
		})
	}

	// Volume mounts (only allow sources under ramdisk)
	for _, vol := range c.Volumes {
		source := strings.SplitN(vol, ":", 2)[0]
		if source != ramdiskPath && !strings.HasPrefix(filepath.Clean(source), ramdiskPath+"/") {
			return fmt.Errorf("volume source must be under %s: %s", ramdiskPath, source)
		}
		hostConfig.Binds = append(hostConfig.Binds, vol)
	}

	// GPU configuration
	if req := parseGPUs(c.GPUs); req != nil {
		hostConfig.DeviceRequests = []container.DeviceRequest{*req}
	}

	// Pull the image via containerd (uses registry mirror from /etc/containerd/certs.d)
	slog.Info("pulling image", "name", c.Name, "image", c.Image)
	if err := pullImageViaContainerd(c.Image); err != nil {
		return fmt.Errorf("pulling image: %w", err)
	}

	slog.Info("creating container", "name", c.Name, "image", c.Image)

	resp, err := cli.ContainerCreate(context.Background(), containerConfig, hostConfig, nil, nil, c.Name)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	if err := cli.ContainerStart(context.Background(), resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("starting container: %w", err)
	}

	slog.Info("started container", "name", c.Name, "id", resp.ID[:12])
	return nil
}

// buildEnv parses env entries and secrets from external config
func buildEnv(envItems []interface{}, secrets []string, extConfig *ExternalConfig) []string {
	var env []string

	// Process env items
	for _, item := range envItems {
		switch v := item.(type) {
		case string:
			// String entry: lookup from external-config env section
			if extConfig != nil && extConfig.Env != nil {
				if val, ok := extConfig.Env[v]; ok {
					env = append(env, v+"="+val)
				} else {
					slog.Warn("env key not found in external config", "key", v)
				}
			} else {
				slog.Warn("env key not found (no external config)", "key", v)
			}
		case map[string]interface{}:
			// Map entry: hardcoded value
			for k, val := range v {
				env = append(env, k+"="+fmt.Sprint(val))
			}
		}
	}

	// Process secrets (lookup from external-config secrets section)
	for _, key := range secrets {
		if extConfig != nil && extConfig.Secrets != nil {
			if val, ok := extConfig.Secrets[key]; ok {
				env = append(env, key+"="+val)
			} else {
				slog.Warn("secret key not found in external config", "key", key)
			}
		} else {
			slog.Warn("secret key not found (no external config)", "key", key)
		}
	}

	return env
}

// parseGPUs parses gpus: "all", "0,1,2,3", true, or count
func parseGPUs(gpus interface{}) *container.DeviceRequest {
	if gpus == nil {
		return nil
	}

	req := &container.DeviceRequest{
		Driver:       "nvidia",
		Capabilities: [][]string{{"gpu"}},
	}

	switch v := gpus.(type) {
	case bool:
		if !v {
			return nil
		}
		req.Count = -1
	case string:
		if v == "all" {
			req.Count = -1
		} else {
			req.DeviceIDs = strings.Split(v, ",")
		}
	case int:
		req.Count = v
	case float64:
		req.Count = int(v)
	default:
		return nil
	}
	return req
}

// parseDuration parses a duration string, returns 0 on error
func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, _ := time.ParseDuration(s)
	return d
}

// This uses containerd's registry mirror configuration from /etc/containerd/certs.d
func pullImageViaContainerd(imageName string) error {
	ctrd, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return fmt.Errorf("connecting to containerd: %w", err)
	}
	defer ctrd.Close()

	// Use "moby" namespace - shared with Docker when containerd-snapshotter is enabled
	ctx := namespaces.WithNamespace(context.Background(), "moby")

	// Timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	// Normalize image name for Docker Hub (containerd requires full reference)
	ref := normalizeImageRef(imageName)

	slog.Debug("pulling via containerd", "ref", ref)

	_, err = ctrd.Pull(ctx, ref, containerd.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("containerd pull: %w", err)
	}

	return nil
}

func normalizeImageRef(image string) string {
	parts := strings.Split(image, "/")
	if len(parts) > 0 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		return image
	}

	// Docker Hub: add docker.io/library/ for official images, docker.io/ for others
	if len(parts) == 1 {
		return "docker.io/library/" + image
	}
	return "docker.io/" + image
}
