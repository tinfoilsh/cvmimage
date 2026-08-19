package containers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/docker/go-units"
	"github.com/moby/moby/api/types/container"
	dockernetwork "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/containernet"
	"tinfoil/internal/runtimeconfig"
	"tinfoil/internal/secretstore"
)

const (
	healthPollInterval         = 5 * time.Second
	defaultPidsLimit     int64 = 65536
	openEgressGwPriority       = 100
)

func setupContainerNetwork(ctx context.Context, cli *client.Client, cfg *Config, debug bool) error {
	for name := range cfg.Networks {
		if err := ensureNetwork(ctx, cli, name); err != nil {
			return err
		}
	}
	if runtimeconfig.ShimUpstreamSet(cfg) {
		if err := ensureShimNetwork(ctx, cli, cfg.ShimCfg.UpstreamContainer); err != nil {
			return err
		}
	}
	return setupContainerNetworkFirewall(ctx, cfg, debug)
}

func PrepareNetworks(ctx context.Context, config *Config, debug bool) error {
	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()
	return setupContainerNetwork(ctx, cli, config, debug)
}

func ensureNetwork(ctx context.Context, cli *client.Client, name string) error {
	_, err := cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if err == nil {
		return nil
	}
	if !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("checking whether docker network %q exists: %w", name, err)
	}
	_, err = cli.NetworkCreate(ctx, name, networkCreateOptions(name))
	if err != nil {
		return fmt.Errorf("creating docker network %q: %w", name, err)
	}
	return nil
}

func ensureShimNetwork(ctx context.Context, cli *client.Client, upstreamContainer string) error {
	result, err := cli.NetworkInspect(ctx, containernet.ShimNetName, client.NetworkInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		_, err = cli.NetworkCreate(ctx, containernet.ShimNetName, networkCreateOptions(containernet.ShimNetName))
		if err != nil {
			return fmt.Errorf("creating docker network %q: %w", containernet.ShimNetName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking whether docker network %q exists: %w", containernet.ShimNetName, err)
	}
	existing := result.Network

	if len(existing.IPAM.Config) != 1 ||
		existing.IPAM.Config[0].Subnet.String() != containernet.ShimNetSubnetCIDR ||
		existing.IPAM.Config[0].Gateway.String() != containernet.ShimNetGatewayIP {
		return fmt.Errorf("docker network %q must use subnet %s", containernet.ShimNetName, containernet.ShimNetSubnetCIDR)
	}
	if len(existing.Containers) > 1 {
		return fmt.Errorf("docker network %q must have at most one attached container, found %d", containernet.ShimNetName, len(existing.Containers))
	}
	for _, c := range existing.Containers {
		if c.Name != upstreamContainer {
			return fmt.Errorf("docker network %q is attached to %q, want upstream container %q", containernet.ShimNetName, c.Name, upstreamContainer)
		}
	}
	return nil
}

func networkCreateOptions(name string) client.NetworkCreateOptions {
	opts := client.NetworkCreateOptions{
		Driver: "bridge",
		Options: map[string]string{
			"com.docker.network.bridge.name": name,
		},
	}
	if name == containernet.ShimNetName {
		opts.IPAM = &dockernetwork.IPAM{
			Config: []dockernetwork.IPAMConfig{{
				Subnet:  netip.MustParsePrefix(containernet.ShimNetSubnetCIDR),
				Gateway: netip.MustParseAddr(containernet.ShimNetGatewayIP),
			}},
		}
	}
	return opts
}

// launchContainersAndWaitHealthy launches all containers in parallel with
// health checking. Each container is tracked as a substage of "containers"
// with per-phase sub-substages (pull, start, healthy).
func LaunchAndWaitHealthy(ctx context.Context, tracker *boot.Tracker, config *Config, extConfig *shimconfig.ExternalConfig, secrets secretstore.Store, debug bool) error {
	return LaunchAndWaitHealthyExcept(ctx, tracker, config, extConfig, secrets, debug, nil)
}

func LaunchAndWaitHealthyExcept(ctx context.Context, tracker *boot.Tracker, config *Config, extConfig *shimconfig.ExternalConfig, secrets secretstore.Store, debug bool, preserved map[string]bool) error {
	if len(config.Containers) == 0 {
		log.Println("No containers to launch")
		tracker.Record(boot.StageContainers, boot.StatusSkipped, 0, "no containers")
		return nil
	}

	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	launchContainers := containersToLaunch(config.Containers, preserved)
	if len(launchContainers) == 0 {
		log.Println("No containers to launch")
		tracker.Record(boot.StageContainers, boot.StatusSkipped, 0, "all containers preserved")
		return nil
	}

	start := time.Now()

	// Initialize substages: one per container, each with phase sub-substages.
	var substages []boot.Stage
	for _, c := range launchContainers {
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

	errs := make([]error, len(launchContainers))
	var wg sync.WaitGroup
	for i, c := range launchContainers {
		wg.Add(1)
		go func(i int, c Container) {
			defer wg.Done()
			errs[i] = runContainer(ctx, cli, c, config, extConfig, secrets, &substages, &mu, flush, debug)
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

func containersToLaunch(configured []Container, preserved map[string]bool) []Container {
	if len(preserved) == 0 {
		return configured
	}
	launch := make([]Container, 0, len(configured))
	for _, current := range configured {
		if !preserved[current.Name] {
			launch = append(launch, current)
		}
	}
	return launch
}

func RemoveManagedExcept(ctx context.Context, config *Config, preserved map[string]bool) error {
	if config == nil {
		return nil
	}
	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()
	var errs []error
	for _, declared := range config.Containers {
		if preserved[declared.Name] {
			continue
		}
		_, err := cli.ContainerRemove(ctx, declared.Name, client.ContainerRemoveOptions{Force: true})
		if err != nil && !cerrdefs.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("removing %s: %w", declared.Name, err))
		}
	}
	return errors.Join(errs...)
}

// runContainer handles the full lifecycle of a single container:
// pull → create+start → wait-healthy. Substage updates are mutex-protected.
func runContainer(
	ctx context.Context,
	cli *client.Client,
	c Container,
	cfg *Config,
	extConfig *shimconfig.ExternalConfig,
	secrets secretstore.Store,
	substages *[]boot.Stage,
	mu *sync.Mutex,
	flush func(),
	debug bool,
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
	if err := pullImage(ctx, cli, c.Image); err != nil {
		detail := fmt.Sprintf("pulling image: %v", err)
		record("pull", boot.StatusFailed, time.Since(pullStart), detail)
		finish(boot.StatusFailed, detail)
		return fmt.Errorf("%s: %s", c.Name, detail)
	}
	record("pull", boot.StatusOK, time.Since(pullStart), "")

	// Create + start
	startPhase := time.Now()
	if err := createAndStartContainer(ctx, cli, c, cfg, extConfig, secrets, debug); err != nil {
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
	ticker := time.NewTicker(healthPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		result, err := cli.ContainerInspect(ctx, c.Name, client.ContainerInspectOptions{})
		info := result.Container
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

// attachOrder returns the bridges to connect to a container. Docker needs
// the first network at ContainerCreate time, so it's returned separately.
// The egress-capable network (if any) goes first; shim-net is appended
// last for the shim's upstream.
func attachOrder(c Container, cfg *Config) (first string, rest []string) {
	var egress string
	var closed []string
	for _, n := range c.Networks {
		if cfg.Networks[n].Egress != "closed" {
			egress = n
			continue
		}
		closed = append(closed, n)
	}
	if egress != "" {
		first = egress
		rest = append(rest, closed...)
	} else if len(closed) > 0 {
		first = closed[0]
		rest = append(rest, closed[1:]...)
	}
	if runtimeconfig.ShimUpstreamSet(cfg) && c.Name == cfg.ShimCfg.UpstreamContainer {
		if first == "" {
			first = containernet.ShimNetName
		} else {
			rest = append(rest, containernet.ShimNetName)
		}
	}
	return first, rest
}

func createAndStartContainer(ctx context.Context, cli *client.Client, c Container, cfg *Config, extConfig *shimconfig.ExternalConfig, secrets secretstore.Store, debug bool) error {
	containerConfig, hostConfig, networkingConfig, rest, err := buildContainerCreateSpec(c, cfg, extConfig, secrets, debug)
	if err != nil {
		return err
	}

	log.Printf("Creating container %s", c.Name)

	resp, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           containerConfig,
		HostConfig:       hostConfig,
		NetworkingConfig: networkingConfig,
		Name:             c.Name,
	})
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	for _, n := range rest {
		ep := endpointSettings(n, gatewayPriorityForNetwork(cfg, n))
		if _, err := cli.NetworkConnect(ctx, n, client.NetworkConnectOptions{
			Container:      resp.ID,
			EndpointConfig: ep,
		}); err != nil {
			return fmt.Errorf("connecting container %s to %s: %w", c.Name, n, err)
		}
	}

	if _, err := cli.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("starting container: %w", err)
	}

	log.Printf("Started container %s (%s)", c.Name, resp.ID[:12])
	return nil
}

func buildContainerCreateSpec(c Container, cfg *Config, extConfig *shimconfig.ExternalConfig, secrets secretstore.Store, debug bool) (*container.Config, *container.HostConfig, *dockernetwork.NetworkingConfig, []string, error) {
	if c.Image == "" {
		return nil, nil, nil, nil, fmt.Errorf("no image specified for container %s", c.Name)
	}

	// Build environment variables
	env := buildEnv(c.Env, c.Secrets, extConfig, secrets)

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

	pidsLimit := c.PidsLimit
	if pidsLimit == nil {
		n := defaultPidsLimit
		pidsLimit = &n
	}

	first, rest := attachOrder(c, cfg)

	// Host configuration
	hostConfig := &container.HostConfig{
		Runtime:        c.Runtime,
		IpcMode:        container.IpcMode(c.IPC),
		PidMode:        container.PidMode(c.PidMode),
		CapAdd:         c.CapAdd,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		ReadonlyRootfs: c.ReadOnly == nil || *c.ReadOnly,
		Tmpfs:          c.Tmpfs,
		Binds:          []string{boot.PublicDir + ":/tinfoil:ro"},
	}
	hostConfig.Resources.PidsLimit = pidsLimit
	if first == "" {
		hostConfig.NetworkMode = "none"
	} else {
		hostConfig.NetworkMode = container.NetworkMode(first)
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
	} else if avail := containerMemoryBytes(&c, cfg); avail > 0 {
		// Matching the kernel's default tmpfs sizing (50% of RAM).
		hostConfig.ShmSize = avail / 2
	}
	if c.Memory != "" {
		if mem, err := units.RAMInBytes(c.Memory); err == nil {
			hostConfig.Resources.Memory = mem
		}
	}
	if c.CPUs > 0 {
		hostConfig.Resources.NanoCPUs = int64(c.CPUs * 1e9)
	}
	for _, device := range c.Devices {
		hostConfig.Devices = append(hostConfig.Devices, container.DeviceMapping{
			PathOnHost: device, PathInContainer: device, CgroupPermissions: "rwm",
		})
	}

	// Volume mounts
	reservedDebugRuntime := runtimeconfig.ReservedDebugRuntimeEnabled(c.Name, debug)
	for _, vol := range c.Volumes {
		hostConfig.Binds = append(hostConfig.Binds, vol)
	}

	if reservedDebugRuntime {
		applyReservedDebugRuntime(containerConfig, hostConfig)
	}

	// GPU configuration
	if req := parseGPUs(c.GPUs); req != nil {
		hostConfig.DeviceRequests = []container.DeviceRequest{*req}
	}

	// Pin the egress-capable network's GwPriority so Docker installs the
	// default route through it; equal priorities are non-deterministic.
	var networkingConfig *dockernetwork.NetworkingConfig
	if first != "" {
		networkingConfig = &dockernetwork.NetworkingConfig{
			EndpointsConfig: map[string]*dockernetwork.EndpointSettings{
				first: endpointSettings(first, gatewayPriorityForNetwork(cfg, first)),
			},
		}
	}

	return containerConfig, hostConfig, networkingConfig, rest, nil
}

func gatewayPriorityForNetwork(cfg *Config, name string) int {
	if cfg != nil && cfg.Networks[name] != nil && cfg.Networks[name].Egress != "closed" {
		return openEgressGwPriority
	}
	return 0
}

func applyReservedDebugRuntime(containerConfig *container.Config, hostConfig *container.HostConfig) {
	hostConfig.NetworkMode = "bridge"
	port := dockernetwork.MustParsePort(reservedDebugPort)
	if containerConfig.ExposedPorts == nil {
		containerConfig.ExposedPorts = dockernetwork.PortSet{}
	}
	containerConfig.ExposedPorts[port] = struct{}{}
	if hostConfig.PortBindings == nil {
		hostConfig.PortBindings = dockernetwork.PortMap{}
	}
	hostConfig.PortBindings[port] = []dockernetwork.PortBinding{{
		HostPort: fmt.Sprintf("%d", reservedDebugHostPort),
	}}
}

func endpointSettings(name string, gwPriority int) *dockernetwork.EndpointSettings {
	ep := &dockernetwork.EndpointSettings{GwPriority: gwPriority}
	if name == containernet.ShimNetName {
		ep.IPAMConfig = &dockernetwork.EndpointIPAMConfig{
			IPv4Address: netip.MustParseAddr(containernet.ShimUpstreamIP),
		}
	}
	return ep
}

// pullImage pulls an image using the Docker SDK with auth from Docker config
func pullImage(ctx context.Context, cli *client.Client, imageName string) error {
	opts := client.ImagePullOptions{}

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
	inspect, err := cli.ImageInspect(ctx, imageName)
	if err != nil {
		return fmt.Errorf("inspect pulled image: %w", err)
	}
	if err := verifyPulledImageDigest(imageName, inspect.RepoDigests); err != nil {
		return err
	}
	return nil
}

func verifyPulledImageDigest(imageName string, repoDigests []string) error {
	named, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return fmt.Errorf("invalid image reference %q: %w", imageName, err)
	}
	expected, ok := named.(reference.Digested)
	if !ok {
		return fmt.Errorf("image reference %q does not contain a digest", imageName)
	}
	for _, repoDigest := range repoDigests {
		actualNamed, err := reference.ParseNormalizedNamed(repoDigest)
		if err != nil {
			continue
		}
		actual, ok := actualNamed.(reference.Digested)
		if ok && actual.Digest() == expected.Digest() {
			return nil
		}
	}
	return fmt.Errorf("pulled image does not advertise requested digest %s", expected.Digest())
}

func containerMemoryBytes(c *Container, cfg *Config) int64 {
	if c.Memory != "" {
		if mem, err := units.RAMInBytes(c.Memory); err == nil {
			return mem
		}
	}
	if cfg != nil && cfg.Memory > 0 {
		return int64(cfg.Memory) * 1024 * 1024
	}
	return 0
}

// buildEnv combines external-config environment entries with resolved secret values.
func buildEnv(envItems []interface{}, secrets []string, extConfig *shimconfig.ExternalConfig, secretValues secretstore.Store) []string {
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

	// Process secrets resolved by tinfoil-boot and held by tinfoil-containers.
	for _, key := range secrets {
		if v := secretValues[key]; v != "" {
			env = append(env, key+"="+v)
		} else {
			log.Printf("Warning: secret key %s not found in secret store", key)
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
