package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/netfilter"
)

type fakeEgressPopulator struct {
	populate func(context.Context) error
}

func (f fakeEgressPopulator) Populate(ctx context.Context) error { return f.populate(ctx) }

func TestFirewallInstallsFixedNetworksBeforePopulation(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"web":     {Egress: "open"},
		"control": {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
	}}
	var events []string
	var got []netfilter.Network
	err := setupContainerNetworkFirewallWith(context.Background(), cfg, false, func(_ context.Context, networks []netfilter.Network, debug bool) error {
		events = append(events, "install")
		got = append([]netfilter.Network(nil), networks...)
		return nil
	}, func() (egressPopulator, error) {
		events = append(events, "load")
		return fakeEgressPopulator{populate: func(context.Context) error {
			events = append(events, "populate")
			return nil
		}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantNetworks := []netfilter.Network{{Name: "control", Egress: netfilter.EgressAllowlist}, {Name: "web", Egress: netfilter.EgressOpen}}
	if !reflect.DeepEqual(got, wantNetworks) {
		t.Fatalf("networks = %#v, want %#v", got, wantNetworks)
	}
	if want := []string{"install", "load", "populate"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("effects = %v, want %v", events, want)
	}
}

func TestFirewallAddsClosedShimNetwork(t *testing.T) {
	cfg := &Config{
		ShimCfg:  &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*NetworkSpec{"web": {Egress: "open"}},
	}
	var got []netfilter.Network
	err := setupContainerNetworkFirewallWith(context.Background(), cfg, false, func(_ context.Context, networks []netfilter.Network, debug bool) error {
		got = append([]netfilter.Network(nil), networks...)
		return nil
	}, func() (egressPopulator, error) { t.Fatal("unexpected egress load"); return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	want := []netfilter.Network{{Name: "web", Egress: netfilter.EgressOpen}, {Name: "shim-net", Egress: netfilter.EgressClosed}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("networks = %#v, want %#v", got, want)
	}
}

func TestFirewallNoAllowlistSkipsPopulation(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{"ipc": {Egress: "closed"}, "web": {Egress: "open"}}}
	loaded := false
	err := setupContainerNetworkFirewallWith(context.Background(), cfg, false, func(context.Context, []netfilter.Network, bool) error { return nil }, func() (egressPopulator, error) {
		loaded = true
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if loaded {
		t.Fatal("loaded egress engine without an allowlist network")
	}
}

func TestFirewallRejectsModeOutsideFixedContract(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{"web": {Egress: "future-mode"}}}
	called := false
	err := setupContainerNetworkFirewallWith(context.Background(), cfg, false, func(context.Context, []netfilter.Network, bool) error {
		called = true
		return nil
	}, func() (egressPopulator, error) { return nil, nil })
	if err == nil || !strings.Contains(err.Error(), "invalid egress mode") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("invalid mode reached the kernel")
	}
}

func TestFirewallPopulationFailureAbortsSetup(t *testing.T) {
	wantErr := errors.New("resolution failed")
	cfg := &Config{Networks: map[string]*NetworkSpec{"control": {Egress: "allowlist"}}}
	err := setupContainerNetworkFirewallWith(context.Background(), cfg, false, func(context.Context, []netfilter.Network, bool) error { return nil }, func() (egressPopulator, error) {
		return fakeEgressPopulator{populate: func(context.Context) error { return wantErr }}, nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("setup error = %v, want %v", err, wantErr)
	}
}

func TestFirewallPopulationHasFixedBootDeadline(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{"control": {Egress: "allowlist"}}}
	err := setupContainerNetworkFirewallWith(context.Background(), cfg, false, func(context.Context, []netfilter.Network, bool) error { return nil }, func() (egressPopulator, error) {
		return fakeEgressPopulator{populate: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("population context has no deadline")
			}
			remaining := time.Until(deadline)
			if remaining > egressInitialPopulationTimeout || remaining < egressInitialPopulationTimeout-time.Second {
				t.Fatalf("population deadline = %s, want %s", remaining, egressInitialPopulationTimeout)
			}
			return nil
		}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFirewallPopulationInheritsBootCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &Config{Networks: map[string]*NetworkSpec{"control": {Egress: "allowlist"}}}
	err := setupContainerNetworkFirewallWith(ctx, cfg, false, func(context.Context, []netfilter.Network, bool) error { return nil }, func() (egressPopulator, error) {
		return fakeEgressPopulator{populate: func(ctx context.Context) error { return ctx.Err() }}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("setup error = %v, want boot cancellation", err)
	}
}

func TestAttachOrderEgressFirstThenClosedThenShim(t *testing.T) {
	cfg := &Config{
		ShimCfg: &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*NetworkSpec{
			"control":  {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
			"ipc-exec": {Egress: "closed"},
			"ipc-a":    {Egress: "closed"},
		},
	}
	first, rest := attachOrder(Container{Name: "api", Networks: []string{"ipc-exec", "control", "ipc-a"}}, cfg)
	if first != "control" {
		t.Errorf("egress network should be first, got %q", first)
	}
	if len(rest) == 0 || rest[len(rest)-1] != "shim-net" {
		t.Errorf("shim-net should be last, got rest=%v", rest)
	}
}

func TestAttachOrderNoNetworksNonShim(t *testing.T) {
	first, rest := attachOrder(Container{Name: "lonely"}, &Config{Networks: map[string]*NetworkSpec{}})
	if first != "" || len(rest) != 0 {
		t.Errorf("unattached non-shim container should get nothing, got %q %v", first, rest)
	}
}

func TestAttachOrderNoNetworksShimUpstreamGetsShimNet(t *testing.T) {
	cfg := &Config{ShimCfg: &shimconfig.Config{UpstreamContainer: "upstream"}, Networks: map[string]*NetworkSpec{}}
	first, rest := attachOrder(Container{Name: "upstream"}, cfg)
	if first != "shim-net" || len(rest) != 0 {
		t.Errorf("unexpected attachment: first=%q rest=%v", first, rest)
	}
}

func TestFixedFirewallDebugForwardContract(t *testing.T) {
	tests := []struct {
		name       string
		debug      bool
		containers []Container
		want       bool
	}{
		{name: "reserved debug", debug: true, containers: []Container{{Name: reservedDebugContainerName}}, want: true},
		{name: "production", containers: []Container{{Name: reservedDebugContainerName}}},
		{name: "generic", debug: true, containers: []Container{{Name: "workload"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			err := setupContainerNetworkFirewallWith(context.Background(), &Config{
				Networks:   map[string]*NetworkSpec{},
				Containers: test.containers,
			}, test.debug, func(_ context.Context, _ []netfilter.Network, debugForward bool) error {
				called = true
				if debugForward != test.want {
					t.Fatalf("debugForward = %t, want %t", debugForward, test.want)
				}
				return nil
			}, func() (egressPopulator, error) { return nil, nil })
			if err != nil || !called {
				t.Fatalf("setup error = %v, called=%t", err, called)
			}
		})
	}
}
