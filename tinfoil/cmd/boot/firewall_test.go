package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
)

type fakeEgressPopulator struct {
	populate func() error
}

func (f fakeEgressPopulator) Populate(context.Context) error {
	return f.populate()
}

func TestFirewall_AllowlistPopulationFollowsNftOnce(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"control": {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
		"metrics": {Egress: "allowlist", Allow: []string{"metrics.tinfoil.sh"}},
	}}
	var events []string
	err := setupContainerNetworkFirewallWith(
		cfg,
		func(string) error {
			events = append(events, "nft")
			return nil
		},
		func() (egressPopulator, error) {
			events = append(events, "load")
			return fakeEgressPopulator{populate: func() error {
				events = append(events, "populate")
				return nil
			}}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nft", "load", "populate"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("effects = %v, want %v", events, want)
	}
}

func TestFirewall_NoAllowlistSkipsPopulation(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"ipc": {Egress: "closed"},
		"web": {Egress: "open"},
	}}
	loaded := false
	err := setupContainerNetworkFirewallWith(
		cfg,
		func(string) error { return nil },
		func() (egressPopulator, error) {
			loaded = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if loaded {
		t.Fatal("loaded egress engine without an allowlist network")
	}
}

func TestFirewall_PopulationFailureAbortsSetup(t *testing.T) {
	wantErr := errors.New("resolution failed")
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"control": {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
	}}
	populateCalls := 0
	err := setupContainerNetworkFirewallWith(
		cfg,
		func(string) error { return nil },
		func() (egressPopulator, error) {
			return fakeEgressPopulator{populate: func() error {
				populateCalls++
				return wantErr
			}}, nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("setup error = %v, want %v", err, wantErr)
	}
	if populateCalls != 1 {
		t.Fatalf("Populate calls = %d, want 1", populateCalls)
	}
}

// renderFirewallScript returns the nft script setupContainerNetworkFirewall
// would commit, minus the runNft call.
func renderFirewallScript(cfg *Config) string {
	var s strings.Builder
	for name, spec := range cfg.Networks {
		writeBridgeRules(&s, name, spec)
	}
	if shimUpstreamSet(cfg) {
		writeBridgeRules(&s, "shim-net", &NetworkSpec{Egress: "closed"})
	}
	return s.String()
}

func TestFirewall_ClosedBridgeHasNoEgressRule(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"ipc-exec": {Egress: "closed"},
	}}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `iif "ipc-exec" oif "ipc-exec" accept`) {
		t.Error("closed bridge should still allow intra-bridge traffic")
	}
	if !strings.Contains(script, `oif "ipc-exec" ct state established`) {
		t.Error("closed bridge should still allow return traffic")
	}
	if !strings.Contains(script, `input iif "ipc-exec" ct state new drop`) {
		t.Error("closed bridge should block container→host")
	}
	if strings.Contains(script, "ip daddr") {
		t.Errorf("closed bridge must not emit egress rules; got:\n%s", script)
	}
}

func TestFirewall_OpenBridgeEmitsPublicAccept(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"web": {Egress: "open"},
	}}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `iif "web" ip daddr != {`) {
		t.Errorf("open bridge should accept public v4; got:\n%s", script)
	}
	if !strings.Contains(script, `iif "web" ip6 daddr != {`) {
		t.Error("open bridge should accept public v6")
	}
}

func TestFirewall_OpenBridgeBlocksNonPublicIPv4Ranges(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"web": {Egress: "open"},
	}}
	script := renderFirewallScript(cfg)
	for _, cidr := range []string{
		"100.64.0.0/10",   // RFC 6598 shared address space.
		"198.18.0.0/15",   // RFC 6890 benchmarking.
		"198.51.100.0/24", // RFC 5737 documentation.
		"224.0.0.0/4",     // RFC 6890 multicast.
		"240.0.0.0/4",     // RFC 6890 reserved.
		"255.255.255.255/32",
	} {
		if !strings.Contains(script, cidr) {
			t.Errorf("open bridge should exclude %s from public egress; got:\n%s", cidr, script)
		}
	}
}

func TestFirewall_AllowlistEmitsSetAndAcceptRule(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"control": {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
	}}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `add set inet tinfoil allow-control`) {
		t.Errorf("allowlist must declare its set; got:\n%s", script)
	}
	if !strings.Contains(script, `iif "control" ip daddr @allow-control accept`) {
		t.Errorf("allowlist must reference its set; got:\n%s", script)
	}
	if !strings.Contains(script, `iif "control" ip daddr {`) {
		t.Error("allowlist must drop private destinations")
	}
}

func TestFirewall_AllowlistDropsNonPublicBeforeAllowSet(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"control": {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
	}}
	script := renderFirewallScript(cfg)
	dropRule := `iif "control" ip daddr {`
	dropIdx := strings.Index(script, dropRule)
	allowIdx := strings.Index(script, `iif "control" ip daddr @allow-control accept`)
	if dropIdx == -1 || allowIdx == -1 {
		t.Fatalf("expected non-public drop before allow set; got:\n%s", script)
	}
	if dropIdx > allowIdx {
		t.Fatalf("non-public drop must precede allow set; got:\n%s", script)
	}
	for _, cidr := range []string{"100.64.0.0/10", "198.18.0.0/15"} {
		if !strings.Contains(script, cidr) {
			t.Errorf("allowlist bridge should drop %s before allow set; got:\n%s", cidr, script)
		}
	}
}

func TestFirewall_ShimNetAlwaysClosed(t *testing.T) {
	cfg := &Config{
		ShimCfg: &shimconfig.Config{UpstreamContainer: "x"},
		Networks: map[string]*NetworkSpec{
			"web": {Egress: "open"},
		},
	}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `iif "shim-net" oif "shim-net" accept`) {
		t.Errorf("shim-net should emit intra-bridge accept; got:\n%s", script)
	}
	if strings.Contains(script, `iif "shim-net" ip daddr !`) {
		t.Error("shim-net must not get an egress-open rule")
	}
}

func TestAttachOrder_EgressFirstThenClosedThenShim(t *testing.T) {
	cfg := &Config{
		ShimCfg: &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*NetworkSpec{
			"control":  {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
			"ipc-exec": {Egress: "closed"},
			"ipc-a":    {Egress: "closed"},
		},
	}
	c := Container{Name: "api", Networks: []string{"ipc-exec", "control", "ipc-a"}}
	first, rest := attachOrder(c, cfg)
	if first != "control" {
		t.Errorf("egress network should be first, got %q", first)
	}
	// shim-net must come last
	if len(rest) == 0 || rest[len(rest)-1] != "shim-net" {
		t.Errorf("shim-net should be last, got rest=%v", rest)
	}
}

func TestAttachOrder_NoNetworksNonShim(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{}}
	c := Container{Name: "lonely"}
	first, rest := attachOrder(c, cfg)
	if first != "" || len(rest) != 0 {
		t.Errorf("unattached non-shim container should get nothing, got %q %v", first, rest)
	}
}

func TestAttachOrder_NoNetworksShimUpstreamGetsShimNet(t *testing.T) {
	cfg := &Config{
		ShimCfg:  &shimconfig.Config{UpstreamContainer: "upstream"},
		Networks: map[string]*NetworkSpec{},
	}
	c := Container{Name: "upstream"}
	first, rest := attachOrder(c, cfg)
	if first != "shim-net" {
		t.Errorf("upstream-with-no-networks should attach to shim-net, got %q", first)
	}
	if len(rest) != 0 {
		t.Errorf("expected no additional networks, got %v", rest)
	}
}
