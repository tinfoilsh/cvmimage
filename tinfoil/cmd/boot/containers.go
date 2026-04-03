package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/go-units"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

const healthPollInterval = 5 * time.Second

// launchContainers starts all containers from the config
func launchContainers(config *Config) error {
	if len(config.Containers) == 0 {
		log.Println("No containers to launch")
		return nil
	}

	extConfig, _ := getExternalConfig()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	log.Printf("Launching %d containers", len(config.Containers))
	var errors []string
	for _, c := range config.Containers {
		log.Printf("Pulling image %s (%s)", c.Name, c.Image)
		if err := pullImage(cli, c.Image); err != nil {
			log.Printf("Error pulling image for %s: %v", c.Name, err)
			errors = append(errors, fmt.Sprintf("%s: pulling image: %v", c.Name, err))
			continue
		}
		if err := createAndStartContainer(cli, c, extConfig); err != nil {
			log.Printf("Error starting container %s: %v", c.Name, err)
			errors = append(errors, fmt.Sprintf("%s: %v", c.Name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to start %d container(s): %s", len(errors), strings.Join(errors, "; "))
	}
	return nil
}

// launchContainersAndWaitHealthy launches all containers in parallel with
// health checking. Each container is tracked as a substage of "containers"
// with per-phase sub-substages (pull, start, healthy).
func launchContainersAndWaitHealthy(tracker *boot.Tracker, config *Config) error {
	if len(config.Containers) == 0 {
		log.Println("No containers to launch")
		tracker.Record(boot.StageContainers, boot.StatusSkipped, 0, "no containers")
		return nil
	}

	extConfig, _ := getExternalConfig()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	start := time.Now()

	// Initialize substages: one per container, each with phase sub-substages.
	var substages []boot.Stage
	for _, c := range config.Containers {
		phases := []boot.Stage{
			{Name: "pull", Status: boot.StatusPending},
			{Name: "start", Status: boot.StatusPending},
		}
		if c.Healthcheck != nil {
			phases = append(phases, boot.Stage{Name: "healthy", Status: boot.StatusPending})
		}
		substages = append(substages, boot.Stage{
			Name:   c.Name,
			Status: boot.StatusPending,
			Stages: phases,
		})
	}
	tracker.RecordSubstages(boot.StageContainers, substages)

	// Launch all containers in parallel. Each goroutine handles the full
	// lifecycle: pull → start → wait-healthy.
	var mu sync.Mutex
	flush := func() { tracker.RecordSubstages(boot.StageContainers, substages) }

	errs := make([]error, len(config.Containers))
	var wg sync.WaitGroup
	for i, c := range config.Containers {
		wg.Add(1)
		go func(i int, c Container) {
			defer wg.Done()
			errs[i] = runContainer(cli, c, extConfig, &substages, &mu, flush)
		}(i, c)
	}
	wg.Wait()

	var failures []string
	for _, err := range errs {
		if err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		detail := strings.Join(failures, "; ")
		tracker.Record(boot.StageContainers, boot.StatusFailed, time.Since(start), detail)
		return fmt.Errorf("container failures: %s", detail)
	}

	tracker.Record(boot.StageContainers, boot.StatusOK, time.Since(start), "")
	return nil
}

// runContainer handles the full lifecycle of a single container:
// pull → create+start → wait-healthy. Substage updates are mutex-protected.
func runContainer(
	cli *client.Client,
	c Container,
	extConfig *shimconfig.ExternalConfig,
	substages *[]boot.Stage,
	mu *sync.Mutex,
	flush func(),
) error {
	cStart := time.Now()

	record := func(phase, status string, d time.Duration, detail string) {
		mu.Lock()
		updateSubstagePhase(substages, c.Name, phase, status, d, detail)
		flush()
		mu.Unlock()
	}
	finish := func(status, detail string) {
		mu.Lock()
		updateSubstage(substages, c.Name, status, time.Since(cStart), detail)
		flush()
		mu.Unlock()
	}

	// Pull
	pullStart := time.Now()
	log.Printf("Pulling image %s (%s)", c.Name, c.Image)
	if err := pullImage(cli, c.Image); err != nil {
		detail := fmt.Sprintf("pulling image: %v", err)
		record("pull", boot.StatusFailed, time.Since(pullStart), detail)
		finish(boot.StatusFailed, detail)
		return fmt.Errorf("%s: %s", c.Name, detail)
	}
	record("pull", boot.StatusOK, time.Since(pullStart), "")

	// Create + start
	startPhase := time.Now()
	if err := createAndStartContainer(cli, c, extConfig); err != nil {
		detail := fmt.Sprintf("starting: %v", err)
		record("start", boot.StatusFailed, time.Since(startPhase), detail)
		finish(boot.StatusFailed, detail)
		return fmt.Errorf("%s: %s", c.Name, detail)
	}
	record("start", boot.StatusOK, time.Since(startPhase), "")

	if c.Healthcheck == nil {
		finish(boot.StatusOK, "")
		return nil
	}

	// Wait for Docker health verdict
	healthStart := time.Now()
	for {
		time.Sleep(healthPollInterval)
		info, err := cli.ContainerInspect(context.Background(), c.Name)
		if err != nil || info.State == nil || info.State.Health == nil {
			continue
		}
		switch info.State.Health.Status {
		case container.Healthy:
			record("healthy", boot.StatusOK, time.Since(healthStart), "")
			finish(boot.StatusOK, "")
			log.Printf("Container %s is healthy", c.Name)
			return nil
		case container.Unhealthy:
			detail := "unhealthy"
			if msg := lastHealthLog(info.State.Health); msg != "" {
				detail = msg
			}
			record("healthy", boot.StatusFailed, time.Since(healthStart), detail)
			finish(boot.StatusFailed, detail)
			log.Printf("Container %s is unhealthy: %s", c.Name, detail)
			return fmt.Errorf("%s: %s", c.Name, detail)
		}
	}
}

func updateSubstage(substages *[]boot.Stage, name, status string, duration time.Duration, detail string) {
	for i := range *substages {
		if (*substages)[i].Name == name {
			(*substages)[i].Status = status
			(*substages)[i].Duration = duration
			(*substages)[i].Detail = detail
			return
		}
	}
}

func updateSubstagePhase(substages *[]boot.Stage, containerName, phase, status string, duration time.Duration, detail string) {
	for i := range *substages {
		if (*substages)[i].Name == containerName {
			for j := range (*substages)[i].Stages {
				if (*substages)[i].Stages[j].Name == phase {
					(*substages)[i].Stages[j].Status = status
					(*substages)[i].Stages[j].Duration = duration
					(*substages)[i].Stages[j].Detail = detail
					return
				}
			}
			return
		}
	}
}

func lastHealthLog(h *container.Health) string {
	if h == nil || len(h.Log) == 0 {
		return ""
	}
	last := h.Log[len(h.Log)-1]
	if last.Output != "" {
		return last.Output
	}
	return fmt.Sprintf("exit %d", last.ExitCode)
}

// createAndStartContainer creates and starts a container (image must already be pulled).
func createAndStartContainer(cli *client.Client, c Container, extConfig *shimconfig.ExternalConfig) error {
	if c.Image == "" {
		return fmt.Errorf("no image specified for container %s", c.Name)
	}

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
		Binds:          []string{boot.PublicDir + ":/tinfoil:ro"},
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

	// The pull response is a stream of JSON messages. Errors during the pull
	// (network failures, disk full, etc.) are reported inside the JSON stream,
	// NOT as Go errors. We must decode and check each message.
	decoder := json.NewDecoder(reader)
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read pull response: %w", err)
		}
		if msg.Error != "" {
			return fmt.Errorf("docker pull failed: %s", msg.Error)
		}
	}
	return nil
}

// buildEnv parses env entries and secrets from external config
func buildEnv(envItems []interface{}, secrets []string, extConfig *shimconfig.ExternalConfig) []string {
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
		if v := extConfig.GetSecret(key); v != "" {
			env = append(env, key+"="+v)
		} else {
			log.Printf("Warning: secret key %s not found in external config", key)
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

func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("Warning: invalid duration %q: %v", s, err)
	}
	return d
}
