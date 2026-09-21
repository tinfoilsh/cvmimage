package containers

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	dockernetwork "github.com/moby/moby/api/types/network"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/containernet"
	"tinfoil/internal/runtimeconfig"
	"tinfoil/internal/secretstore"
)

func TestAttestedKeyMountsAreExclusiveReadOnly(t *testing.T) {
	cfg := &Config{CVMVersion: "0.15.0", AttestedKeys: []runtimeconfig.AttestedKey{
		{ID: "ssh", Key: "ecdsa-p256"}, {ID: "vpn", Key: "x25519"},
	}, Containers: []Container{
		{Name: "ssh-app", Image: "app", Keys: []string{"ssh"}, Tmpfs: map[string]string{"/run": ""}},
		{Name: "vpn-app", Image: "app", Keys: []string{"vpn"}},
		{Name: "ungranted", Image: "app"},
	}}
	for _, c := range cfg.Containers {
		_, host, _, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		var private []string
		for _, mount := range host.Binds {
			if strings.HasPrefix(mount, boot.PrivateDir) {
				private = append(private, mount)
			}
		}
		if len(private) != len(c.Keys) {
			t.Fatalf("container %s received unrelated private mounts: %v", c.Name, private)
		}
		for _, id := range c.Keys {
			want := boot.AttestedKeysDir + "/" + id + ":" + runtimeconfig.AttestedKeysContainerDir + "/" + id + ":ro"
			if !slices.Contains(private, want) {
				t.Fatalf("missing read-only grant %s", want)
			}
		}
	}
}

func TestOnlyOptedInAdminSSHBecomesDirect(t *testing.T) {
	for _, test := range []struct {
		name                          string
		admin, inbound, debug, direct bool
	}{
		{"opt in", true, true, false, true},
		{"no inbound", true, false, false, false},
		{"ordinary container", false, true, false, false},
		{"debug suppresses production mapping", true, true, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := Container{Name: "workspace", Image: "app", CVMAdmin: test.admin, Networks: []string{"dev"}, Ports: []string{"22:22", "3000:3000"}}
			cfg := &Config{CVMVersion: "0.15.0", Containers: []Container{c}, Networks: map[string]*runtimeconfig.NetworkSpec{"dev": {Egress: "closed"}}}
			if test.inbound {
				cfg.CVMNetwork.InboundPorts = []int{22}
			}
			_, host, _, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, test.debug)
			if err != nil {
				t.Fatal(err)
			}
			ssh := host.PortBindings[dockernetwork.MustParsePort("22/tcp")][0]
			app := host.PortBindings[dockernetwork.MustParsePort("3000/tcp")][0]
			if ssh.HostIP.IsValid() == test.direct || app.HostIP.String() != containernet.PublishedHostIP {
				t.Fatalf("wrong exposure: ssh=%+v app=%+v", ssh, app)
			}
		})
	}
}

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
		secretstore.Store{"API_KEY": "from-handoff"},
	)

	want := map[string]bool{
		"DOMAIN=test.example.com": true,
		"STATIC=value":            true,
		"API_KEY=from-handoff":    true,
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
	env := buildEnv([]interface{}{"FOO"}, []string{"BAR"}, ext, nil)
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

	containerConfig, hostConfig, networkingConfig, rest, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, true)
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
	if bindings[0].HostIP.IsValid() {
		t.Fatalf("HostIP = %s, want unset", bindings[0].HostIP)
	}
	if len(hostConfig.Devices) != 0 {
		t.Fatalf("Devices = %v, want no synthesized device mappings", hostConfig.Devices)
	}
}

func TestBuildContainerCreateSpec_ProductionInstallerKeepsRuntimeClosed(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{}}
	c := Container{
		Name:  reservedDebugContainerName,
		Image: "example.invalid/installer",
	}

	containerConfig, hostConfig, _, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	if len(containerConfig.ExposedPorts) != 0 {
		t.Fatalf("ExposedPorts = %v, want none in production", containerConfig.ExposedPorts)
	}
	if len(hostConfig.PortBindings) != 0 {
		t.Fatalf("PortBindings = %v, want none in production", hostConfig.PortBindings)
	}
	if len(hostConfig.Devices) != 0 {
		t.Fatalf("Devices = %v, want no synthesized device mappings", hostConfig.Devices)
	}
}

func TestBuildContainerCreateSpec_CVMAdmin(t *testing.T) {
	for _, debug := range []bool{false, true} {
		for _, name := range []string{"sandbox", reservedDebugContainerName} {
			c := Container{
				Name: name, Image: "example.invalid/admin", CVMAdmin: true,
				Networks: []string{"dev"}, Ports: []string{"2022:2222"},
				Volumes: []string{"workspace:/workspace"},
			}
			cfg := &Config{
				ShimCfg: &shimconfig.Config{UpstreamContainer: name}, Containers: []Container{c},
				Networks: map[string]*NetworkSpec{"dev": {Egress: "open"}},
				Volumes:  []runtimeconfig.VolumeSpec{{Name: "workspace"}},
			}
			cc, hc, network, rest, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, debug)
			if err != nil {
				t.Fatal(err)
			}
			if cc.User != "0:0" || !hc.Privileged || hc.PidMode != "" || hc.NetworkMode != "dev" || hc.ReadonlyRootfs {
				t.Fatalf("admin profile: user=%q host=%+v", cc.User, hc)
			}
			if len(hc.CapDrop) != 0 || len(hc.SecurityOpt) != 1 || hc.SecurityOpt[0] != "no-new-privileges:false" {
				t.Fatalf("admin privilege restrictions: caps=%v security=%v", hc.CapDrop, hc.SecurityOpt)
			}
			if network == nil || len(network.EndpointsConfig) != 1 || network.EndpointsConfig["dev"] == nil || network.EndpointsConfig["dev"].GwPriority != openEgressGwPriority || !slices.Equal(rest, []string{containernet.ShimNetName}) {
				t.Fatalf("admin lost declared egress or shim bridge: network=%+v rest=%v", network, rest)
			}
			port := dockernetwork.MustParsePort("2222/tcp")
			bindings := hc.PortBindings[port]
			_, exposed := cc.ExposedPorts[port]
			if !exposed || len(cc.ExposedPorts) != 1 || len(hc.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostPort != "2022" || bindings[0].HostIP.String() != containernet.PublishedHostIP {
				t.Fatalf("admin SSH must retain loopback-only publishing: exposed=%v bindings=%v", cc.ExposedPorts, hc.PortBindings)
			}
			if want := []string{boot.PublicDir + ":/tinfoil:ro", boot.VolumeDataDir + "/workspace:/workspace:rslave", boot.VolumeControlDir + "/workspace:" + boot.VolumeControlDir + "/workspace:ro"}; !slices.Equal(hc.Binds, want) {
				t.Fatalf("admin must have only ordinary declared mounts: got %v, want %v", hc.Binds, want)
			}
			readOnly := true
			c.ReadOnly = &readOnly
			_, hc, _, _, err = buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, debug)
			if err != nil || !hc.ReadonlyRootfs {
				t.Fatalf("explicit read_only lost: host=%+v err=%v", hc, err)
			}
			c.Networks, c.Ports, cfg.ShimCfg = nil, nil, nil
			_, hc, network, rest, err = buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, debug)
			if err != nil || hc.NetworkMode != "none" || network != nil || len(rest) != 0 || len(hc.PortBindings) != 0 {
				t.Fatalf("admin without networks must remain disconnected: host=%+v network=%+v rest=%v err=%v", hc, network, rest, err)
			}
		}
	}
}

func TestCVMAdminDoesNotChangeOtherContainers(t *testing.T) {
	c := Container{Name: "app", Image: "example.invalid/app"}
	cfg := &Config{
		ShimCfg:    &shimconfig.Config{UpstreamContainer: "app"},
		Containers: []Container{c, {Name: "admin", CVMAdmin: true}},
	}
	cc, hc, network, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if hc.Privileged || hc.PidMode == "host" || !hc.ReadonlyRootfs || cc.User != "" || !slices.Contains(hc.CapDrop, "ALL") || !slices.Contains(hc.SecurityOpt, "no-new-privileges:true") {
		t.Fatalf("ordinary container privileges changed: user=%q host=%+v", cc.User, hc)
	}
	if !runtimeconfig.ShimUpstreamSet(cfg) || network == nil || hc.NetworkMode != containernet.ShimNetName {
		t.Fatalf("ordinary upstream lost shim-net: host=%+v network=%+v", hc, network)
	}
	if slices.Contains(hc.Binds, debugDockerSocketBind) || slices.Contains(hc.Binds, "/:/host") {
		t.Fatalf("ordinary container received admin binds: %v", hc.Binds)
	}
}

func TestBuildContainerCreateSpec_BindsOnlyGrantedModels(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{}}
	c := Container{
		Name:   "inference",
		Image:  "example.invalid/inference",
		Models: []string{"private-model"},
	}

	_, hostConfig, _, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	want := boot.PrivateModelsDir + "/private-model:" + boot.ContainerModelsDir + "/private-model:ro"
	if !slices.Contains(hostConfig.Binds, want) {
		t.Fatalf("Binds = %v, want %q", hostConfig.Binds, want)
	}

	_, ungrantedHostConfig, _, _, err := buildContainerCreateSpec(Container{
		Name:  "sidecar",
		Image: "example.invalid/sidecar",
	}, cfg, &shimconfig.ExternalConfig{}, nil, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	for _, bind := range ungrantedHostConfig.Binds {
		if strings.HasPrefix(bind, boot.PrivateModelsDir+"/") {
			t.Fatalf("ungranted Binds = %v", ungrantedHostConfig.Binds)
		}
	}
}

func TestBuildContainerCreateSpec_PublishesDeclaredPorts(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{"app": {Egress: "closed"}}}
	c := Container{Name: "sandbox", Image: "example.invalid/sandbox", Networks: []string{"app"}, Ports: []string{"2022:22"}}

	containerConfig, hostConfig, _, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	port := dockernetwork.MustParsePort("22/tcp")
	if _, ok := containerConfig.ExposedPorts[port]; !ok {
		t.Fatalf("ExposedPorts = %v, want %s", containerConfig.ExposedPorts, port)
	}
	bindings := hostConfig.PortBindings[port]
	if len(bindings) != 1 || bindings[0].HostPort != "2022" {
		t.Fatalf("PortBindings[%s] = %v, want host port 2022", port, bindings)
	}
	if bindings[0].HostIP.String() != containernet.PublishedHostIP {
		t.Fatalf("HostIP = %s, want %s", bindings[0].HostIP, containernet.PublishedHostIP)
	}
}

func TestBuildContainerCreateSpec_DeclaredVolumeBecomesPropagatedBind(t *testing.T) {
	cfg := &Config{
		Networks: map[string]*NetworkSpec{},
		Volumes:  []runtimeconfig.VolumeSpec{{Name: "workspace"}},
	}
	c := Container{
		Name:    "app",
		Image:   "example.invalid/app",
		Volumes: []string{"workspace:/workspace", "other:/other"},
	}

	_, hostConfig, _, _, err := buildContainerCreateSpec(c, cfg, &shimconfig.ExternalConfig{}, nil, false)
	if err != nil {
		t.Fatalf("buildContainerCreateSpec: %v", err)
	}
	for _, want := range []string{
		boot.VolumeDataDir + "/workspace:/workspace:rslave",
		boot.VolumeControlDir + "/workspace:" + boot.VolumeControlDir + "/workspace:ro",
		"other:/other",
	} {
		if !slices.Contains(hostConfig.Binds, want) {
			t.Fatalf("Binds = %v, want %q", hostConfig.Binds, want)
		}
	}
	if slices.Contains(hostConfig.Binds, "workspace:/workspace") {
		t.Fatalf("Binds = %v, want the declared volume resolved to its measured mount", hostConfig.Binds)
	}
}
