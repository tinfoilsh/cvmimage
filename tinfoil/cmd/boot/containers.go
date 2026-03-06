package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/go-units"
)

// launchContainers starts all containers from the config
func launchContainers(config *Config) error {
	if len(config.Containers) == 0 {
		log.Println("No containers to launch")
		return nil
	}

	// Load external config once for env/secrets expansion
	extConfig, _ := getExternalConfig() // nil is fine, we'll warn per-key

	log.Printf("Launching %d containers", len(config.Containers))
	var errors []string
	for _, c := range config.Containers {
		if err := startContainer(c, extConfig); err != nil {
			log.Printf("Error starting container %s: %v", c.Name, err)
			errors = append(errors, fmt.Sprintf("%s: %v", c.Name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to start %d container(s): %s", len(errors), strings.Join(errors, "; "))
	}
	return nil
}

// startContainer starts a Docker container using the Docker SDK
func startContainer(c Container, extConfig *ExternalConfig) error {
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
	networkMode := c.NetworkMode
	if networkMode == "" {
		networkMode = "host" // Default to host networking
	}
	hostConfig := &container.HostConfig{
		NetworkMode:    container.NetworkMode(networkMode),
		Runtime:        c.Runtime,
		IpcMode:        container.IpcMode(c.IPC),
		PidMode:        container.PidMode(c.PidMode),
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

	// Volume mounts
	for _, vol := range c.Volumes {
		hostConfig.Binds = append(hostConfig.Binds, vol)
	}

	// GPU configuration
	if req := parseGPUs(c.GPUs); req != nil {
		hostConfig.DeviceRequests = []container.DeviceRequest{*req}
	}

	// Pull the image via Docker
	log.Printf("Pulling image %s (%s)", c.Name, c.Image)
	if err := pullImage(cli, c.Image); err != nil {
		return fmt.Errorf("pulling image: %w", err)
	}

	log.Printf("Creating container %s", c.Name)

	resp, err := cli.ContainerCreate(context.Background(), containerConfig, hostConfig, nil, nil, c.Name)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	if err := cli.ContainerStart(context.Background(), resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("starting container: %w", err)
	}

	log.Printf("Started container %s (%s)", c.Name, resp.ID[:12])
	return nil
}

// pullImage pulls an image using the Docker SDK with auth from Docker config
func pullImage(cli *client.Client, imageName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	opts := image.PullOptions{}

	// Extract registry host and get auth
	host := "docker.io"
	if parts := strings.Split(imageName, "/"); len(parts) > 1 && strings.Contains(parts[0], ".") {
		host = parts[0]
	}
	if cfg, err := dockerconfig.Load(dockerconfig.Dir()); err == nil {
		if auth, err := cfg.GetAuthConfig(host); err == nil && auth.Username != "" {
			encoded, _ := json.Marshal(auth)
			opts.RegistryAuth = base64.URLEncoding.EncodeToString(encoded)
		}
	}

	reader, err := cli.ImagePull(ctx, imageName, opts)
	if err != nil {
		return fmt.Errorf("docker pull: %w", err)
	}
	defer reader.Close()

	_, err = io.Copy(io.Discard, reader)
	return err
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
					log.Printf("Warning: env key %s not found in external config", v)
				}
			} else {
				log.Printf("Warning: env key %s not found (no external config)", v)
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
				log.Printf("Warning: secret key %s not found in external config", key)
			}
		} else {
			log.Printf("Warning: secret key %s not found (no external config)", key)
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
