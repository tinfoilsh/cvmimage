package containers

import (
	"slices"
	"strings"
	"testing"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	dockernetwork "github.com/moby/moby/api/types/network"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/containernet"
)

func TestParseGPUs(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		wantNil   bool
		wantCount int
		wantIDs   []string
	}{
		{"nil", nil, true, 0, nil},
		{"false", false, true, 0, nil},
		{"true", true, false, -1, nil},
		{"all", "all", false, -1, nil},
		{"specific ids", "0,1,2", false, 0, []string{"0", "1", "2"}},
		{"int count", 4, false, 4, nil},
		{"float count", float64(8), false, 8, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := parseGPUs(tt.input)
			if tt.wantNil {
				if req != nil {
					t.Fatalf("expected nil, got %+v", req)
				}
				return
			}
			if req == nil {
				t.Fatal("expected non-nil DeviceRequest")
			}
			if req.Count != tt.wantCount {
				t.Errorf("count: got %d, want %d", req.Count, tt.wantCount)
			}
			if tt.wantIDs != nil {
				if len(req.DeviceIDs) != len(tt.wantIDs) {
					t.Fatalf("device IDs: got %v, want %v", req.DeviceIDs, tt.wantIDs)
				}
				for i, id := range req.DeviceIDs {
					if id != tt.wantIDs[i] {
						t.Errorf("device ID[%d]: got %q, want %q", i, id, tt.wantIDs[i])
					}
				}
			}
		})
	}
}

func TestVerifyPulledImageDigest(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, test := range []struct {
		name        string
		image       string
		repoDigests []string
		wantErr     bool
	}{
		{name: "matching repository", image: "example.com/team/app@" + digest, repoDigests: []string{"example.com/team/app@" + digest}},
		{name: "matching canonical digest", image: "app@" + digest, repoDigests: []string{"docker.io/library/app@" + digest}},
		{name: "missing digest", image: "example.com/team/app:latest", repoDigests: []string{"example.com/team/app@" + digest}, wantErr: true},
		{name: "mismatch", image: "example.com/team/app@" + digest, repoDigests: []string{"example.com/team/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, wantErr: true},
		{name: "empty inspect result", image: "example.com/team/app@" + digest, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyPulledImageDigest(test.image, test.repoDigests)
			if test.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyPulledImagePolicyAllowsDebugTags(t *testing.T) {
	if err := verifyPulledImagePolicy("example.com/team/app:latest", nil, true); err != nil {
		t.Fatalf("debug tag rejected: %v", err)
	}
	if err := verifyPulledImagePolicy("example.com/team/app:latest", nil, false); err == nil {
		t.Fatal("production tag accepted")
	}
}

func TestBuildEnv(t *testing.T) {
	ext := &shimconfig.ExternalConfig{
		Env:     map[string]string{"DOMAIN": "test.example.com", "PORT": "8080"},
		Secrets: map[string]string{"API_KEY": "sk-123", "DB_PASS": "secret"},
	}

	env := buildEnv(
		[]interface{}{
			"DOMAIN",
			map[string]interface{}{"STATIC": "value"},
			"MISSING_KEY",
		},
		[]string{"API_KEY", "MISSING_SECRET"},
		ext,
	)

	want := map[string]bool{
		"DOMAIN=test.example.com": true,
		"STATIC=value":            true,
		"API_KEY=sk-123":          true,
	}
	for _, e := range env {
		if !want[e] {
			t.Errorf("unexpected env entry: %s", e)
		}
		delete(want, e)
	}
	for k := range want {
		t.Errorf("missing env entry: %s", k)
	}
}

func TestBuildEnvNilConfig(t *testing.T) {
	ext := &shimconfig.ExternalConfig{}
	env := buildEnv([]interface{}{"FOO"}, []string{"BAR"}, ext)
	if len(env) != 0 {
		t.Errorf("expected empty env with nil maps, got %v", env)
	}
}

func TestContainerMemoryBytes(t *testing.T) {
	const mib = int64(1024 * 1024)
	tests := []struct {
		name string
		c    Container
		cfg  *Config
		want int64
	}{
		{"explicit container limit", Container{Memory: "2g"}, &Config{Memory: 8192}, 2 * 1024 * mib},
		{"falls back to enclave memory", Container{}, &Config{Memory: 8192}, 8192 * mib},
		{"explicit overrides enclave", Container{Memory: "512m"}, &Config{Memory: 8192}, 512 * mib},
		{"unparseable container limit falls back", Container{Memory: "lots"}, &Config{Memory: 4096}, 4096 * mib},
		{"nothing known", Container{}, &Config{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containerMemoryBytes(&tt.c, tt.cfg); got != tt.want {
				t.Errorf("containerMemoryBytes() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"", 0},
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"invalid", 0},
	}
	for _, tt := range tests {
		got := parseDuration(tt.input)
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestNetworkCreateOptionsStaticShimNet(t *testing.T) {
	opts := networkCreateOptions(containernet.ShimNetName)
	if opts.IPAM == nil || len(opts.IPAM.Config) != 1 {
		t.Fatalf("expected static shim-net IPAM config, got %+v", opts.IPAM)
	}
	if got := opts.IPAM.Config[0].Subnet.String(); got != containernet.ShimNetSubnetCIDR {
		t.Errorf("subnet: got %q, want %q", got, containernet.ShimNetSubnetCIDR)
	}
	if got := opts.IPAM.Config[0].Gateway.String(); got != containernet.ShimNetGatewayIP {
		t.Errorf("gateway: got %q, want %q", got, containernet.ShimNetGatewayIP)
	}
}

func TestEndpointSettingsPinsShimUpstreamIP(t *testing.T) {
	ep := endpointSettings(containernet.ShimNetName, 0)
	if ep.IPAMConfig == nil {
		t.Fatal("expected shim-net endpoint IPAM config")
	}
	if got := ep.IPAMConfig.IPv4Address.String(); got != containernet.ShimUpstreamIP {
		t.Errorf("upstream IP: got %q, want %q", got, containernet.ShimUpstreamIP)
	}

	regular := endpointSettings("web", 100)
	if regular.IPAMConfig != nil {
		t.Fatalf("regular networks should not pin IPAM, got %+v", regular.IPAMConfig)
	}
	if regular.GwPriority != 100 {
		t.Errorf("GwPriority: got %d, want 100", regular.GwPriority)
	}
}

func TestBuildContainerCreateSpec_DebugInstallerGetsFixedRuntime(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{}}
	c := Container{
		Name:    reservedDebugContainerName,
		Image:   "example.invalid/installer",
		Volumes: []string{debugDockerSocketBind},
	}

	containerConfig, hostConfig, networkingConfig, rest, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, true)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	if networkingConfig != nil {
		t.Fatalf("expected no networking config, got %+v", networkingConfig)
	}
	if len(rest) != 0 {
		t.Fatalf("expected no follow-on networks, got %v", rest)
	}
	if hostConfig.NetworkMode != container.NetworkMode("bridge") {
		t.Fatalf("NetworkMode = %q, want bridge", hostConfig.NetworkMode)
	}
	if !hostConfig.ReadonlyRootfs {
		t.Fatal("ReadonlyRootfs = false, want true default")
	}
	if len(hostConfig.CapDrop) != 1 || hostConfig.CapDrop[0] != "ALL" {
		t.Fatalf("CapDrop = %v, want [ALL]", hostConfig.CapDrop)
	}
	if !slices.Contains(hostConfig.SecurityOpt, "no-new-privileges:true") {
		t.Fatalf("SecurityOpt = %v, want no-new-privileges", hostConfig.SecurityOpt)
	}
	if !slices.Contains(hostConfig.Binds, debugDockerSocketBind) {
		t.Fatalf("Binds = %v, want exact docker socket bind", hostConfig.Binds)
	}

	port := dockernetwork.MustParsePort(reservedDebugPort)
	if _, ok := containerConfig.ExposedPorts[port]; !ok {
		t.Fatalf("ExposedPorts = %v, want %s", containerConfig.ExposedPorts, port)
	}
	bindings := hostConfig.PortBindings[port]
	if len(bindings) != 1 || bindings[0].HostPort != "2222" {
		t.Fatalf("PortBindings[%s] = %v, want host port 2222", port, bindings)
	}
	if len(hostConfig.Devices) != 1 {
		t.Fatalf("Devices = %v, want one synthesized serial mapping", hostConfig.Devices)
	}
	if got := hostConfig.Devices[0]; got.PathOnHost != reservedDebugSerialDevice || got.PathInContainer != reservedDebugSerialDevice || got.CgroupPermissions != "rw" {
		t.Fatalf("Devices[0] = %+v, want exact /dev/hvc1 rw mapping", got)
	}
}

func TestBuildContainerCreateSpec_ProductionInstallerKeepsRuntimeClosed(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{}}
	c := Container{
		Name:  reservedDebugContainerName,
		Image: "example.invalid/installer",
	}

	containerConfig, hostConfig, _, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	if len(containerConfig.ExposedPorts) != 0 {
		t.Fatalf("ExposedPorts = %v, want none in production", containerConfig.ExposedPorts)
	}
	if len(hostConfig.PortBindings) != 0 {
		t.Fatalf("PortBindings = %v, want none in production", hostConfig.PortBindings)
	}
	for _, dev := range hostConfig.Devices {
		if dev.PathOnHost == reservedDebugSerialDevice || dev.PathInContainer == reservedDebugSerialDevice {
			t.Fatalf("Devices = %v, want no synthesized serial device in production", hostConfig.Devices)
		}
	}
}

func TestValidateImageMetadata(t *testing.T) {
	tests := []struct {
		name    string
		config  *dockerspec.DockerOCIImageConfig
		wantErr bool
	}{
		{name: "clean", config: &dockerspec.DockerOCIImageConfig{}},
		{name: "nil", config: nil, wantErr: true},
		{name: "healthcheck", config: &dockerspec.DockerOCIImageConfig{DockerOCIImageConfigExt: dockerspec.DockerOCIImageConfigExt{Healthcheck: &dockerspec.HealthcheckConfig{Test: []string{"CMD", "true"}}}}, wantErr: true},
		{name: "volume", config: &dockerspec.DockerOCIImageConfig{ImageConfig: ocispec.ImageConfig{Volumes: map[string]struct{}{`/data`: {}}}}, wantErr: true},
		{name: "nvidia environment", config: &dockerspec.DockerOCIImageConfig{ImageConfig: ocispec.ImageConfig{Env: []string{"NVIDIA_VISIBLE_DEVICES=all"}}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateImageMetadata(test.config)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateImageMetadata() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestBuildContainerCreateSpecNeutralizesImageControls(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{}}
	containerConfig, _, _, _, err := buildContainerCreateSpec(Container{
		Name:  "app",
		Image: "example.invalid/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Env: []interface{}{
			"NVIDIA_VISIBLE_DEVICES=all",
			"NVIDIA_DRIVER_CAPABILITIES=all",
		},
	}, cfg, &shimconfig.ExternalConfig{}, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	if got := containerConfig.Healthcheck.Test; !slices.Equal(got, []string{"NONE"}) {
		t.Fatalf("Healthcheck.Test = %v, want [NONE]", got)
	}
	if got := environmentValue(containerConfig.Env, "NVIDIA_VISIBLE_DEVICES"); got != "none" {
		t.Fatalf("NVIDIA_VISIBLE_DEVICES = %q, want none", got)
	}
	if got := environmentValue(containerConfig.Env, "NVIDIA_DRIVER_CAPABILITIES"); got != "compute,utility" {
		t.Fatalf("NVIDIA_DRIVER_CAPABILITIES = %q, want compute,utility", got)
	}
}

func TestVerifyCreatedContainerPolicy(t *testing.T) {
	expectedConfig := &container.Config{
		Env:         []string{"NVIDIA_VISIBLE_DEVICES=none", "NVIDIA_DRIVER_CAPABILITIES=compute,utility"},
		Healthcheck: &container.HealthConfig{Test: []string{"NONE"}},
	}
	expectedHost := &container.HostConfig{
		ReadonlyRootfs: true,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
	}
	valid := func() container.InspectResponse {
		return container.InspectResponse{
			Config:     expectedConfig,
			HostConfig: expectedHost,
		}
	}
	if err := verifyCreatedContainerPolicy(expectedConfig, expectedHost, valid()); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*container.InspectResponse)
	}{
		{name: "privileged", mutate: func(actual *container.InspectResponse) {
			actual.HostConfig = cloneHostConfig(expectedHost)
			actual.HostConfig.Privileged = true
		}},
		{name: "image volume", mutate: func(actual *container.InspectResponse) {
			actual.Config = cloneContainerConfig(expectedConfig)
			actual.Config.Volumes = map[string]struct{}{`/data`: {}}
		}},
		{name: "nvidia environment", mutate: func(actual *container.InspectResponse) {
			actual.Config = cloneContainerConfig(expectedConfig)
			actual.Config.Env[0] = "NVIDIA_VISIBLE_DEVICES=all"
		}},
		{name: "runtime", mutate: func(actual *container.InspectResponse) {
			actual.HostConfig = cloneHostConfig(expectedHost)
			actual.HostConfig.Runtime = "nvidia"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := valid()
			test.mutate(&actual)
			if err := verifyCreatedContainerPolicy(expectedConfig, expectedHost, actual); err == nil {
				t.Fatal("policy mismatch accepted")
			}
		})
	}
}

func TestLastHealthLogRedactsOutput(t *testing.T) {
	health := &container.Health{Log: []*container.HealthcheckResult{{ExitCode: 17, Output: "secret material"}}}
	if got := lastHealthLog(health); got != "exit 17" {
		t.Fatalf("lastHealthLog() = %q, want exit status only", got)
	}
}

func cloneContainerConfig(config *container.Config) *container.Config {
	clone := *config
	clone.Env = slices.Clone(config.Env)
	return &clone
}

func cloneHostConfig(config *container.HostConfig) *container.HostConfig {
	clone := *config
	clone.CapDrop = slices.Clone(config.CapDrop)
	clone.SecurityOpt = slices.Clone(config.SecurityOpt)
	return &clone
}

func TestBuildContainerCreateSpecMountsOnlyAssignedModels(t *testing.T) {
	const rootHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const modelRef = rootHash + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	cfg := &Config{
		Networks: map[string]*NetworkSpec{},
		Models: []ModelSpec{
			{Name: "assigned", Repo: "org/assigned@v1", MWP: modelRef},
			{Name: "other", Repo: "org/other@v1", MWP: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb_4096_0eefa619-50b7-588f-a072-d405fb439d36"},
		},
	}
	_, hostConfig, _, _, err := buildContainerCreateSpec(Container{
		Name:   "app",
		Image:  "example.invalid/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Models: []string{"assigned"},
	}, cfg, &shimconfig.ExternalConfig{}, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	if slices.Contains(hostConfig.Binds, boot.PublicDir+":/tinfoil:ro") {
		t.Fatalf("broad public ramdisk bind remains: %v", hostConfig.Binds)
	}
	for _, bind := range []string{
		boot.ConfigPath + ":/tinfoil/config.yml:ro",
		boot.AttestationPath + ":/tinfoil/attestation.json:ro",
		boot.ContainerStatusPath + ":/tinfoil/container-status.json:ro",
		boot.MWPDir + "/mwp-" + rootHash + ":/tinfoil/mwp/mwp-" + rootHash + ":ro",
		boot.MWPDir + "/mwp-" + rootHash + ":/tinfoil/mpk/mpk-" + rootHash + ":ro",
	} {
		if !slices.Contains(hostConfig.Binds, bind) {
			t.Fatalf("Binds = %v, missing %q", hostConfig.Binds, bind)
		}
	}
	for _, bind := range hostConfig.Binds {
		if strings.Contains(bind, strings.Repeat("b", 64)) {
			t.Fatalf("unassigned model exposed through %q", bind)
		}
	}
}
