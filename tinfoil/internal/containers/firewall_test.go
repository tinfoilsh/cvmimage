package containers

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
)

type fakeEgressPopulator struct {
	populate func(context.Context) error
}

func (f fakeEgressPopulator) Populate(ctx context.Context) error { return f.populate(ctx) }

func TestFirewallAllowlistPopulationFollowsPolicyOnce(t *testing.T) {
	config := &Config{Networks: map[string]*NetworkSpec{
		"control": {Egress: "allowlist"},
		"metrics": {Egress: "allowlist"},
	}}
	var events []string
	err := setupContainerNetworkFirewallWith(context.Background(), config, false,
		func(*Config, bool) error { events = append(events, "firewall"); return nil },
		func() (egressPopulator, error) {
			events = append(events, "load")
			return fakeEgressPopulator{populate: func(context.Context) error {
				events = append(events, "populate")
				return nil
			}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"firewall", "load", "populate"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("effects = %v, want %v", events, want)
	}
}

func TestFirewallNoAllowlistSkipsPopulation(t *testing.T) {
	config := &Config{Networks: map[string]*NetworkSpec{"ipc": {Egress: "closed"}}}
	loaded := false
	err := setupContainerNetworkFirewallWith(context.Background(), config, false,
		func(*Config, bool) error { return nil },
		func() (egressPopulator, error) { loaded = true; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if loaded {
		t.Fatal("loaded egress engine without an allowlist network")
	}
}

func TestFirewallPopulationFailureAbortsSetup(t *testing.T) {
	wantErr := errors.New("resolution failed")
	config := &Config{Networks: map[string]*NetworkSpec{"control": {Egress: "allowlist"}}}
	err := setupContainerNetworkFirewallWith(context.Background(), config, false,
		func(*Config, bool) error { return nil },
		func() (egressPopulator, error) {
			return fakeEgressPopulator{populate: func(context.Context) error { return wantErr }}, nil
		})
	if !errors.Is(err, wantErr) {
		t.Fatalf("setup error = %v, want %v", err, wantErr)
	}
}

func TestFirewallPopulationHasFixedDeadline(t *testing.T) {
	config := &Config{Networks: map[string]*NetworkSpec{"control": {Egress: "allowlist"}}}
	err := setupContainerNetworkFirewallWith(context.Background(), config, false,
		func(*Config, bool) error { return nil },
		func() (egressPopulator, error) {
			return fakeEgressPopulator{populate: func(ctx context.Context) error {
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > egressInitialPopulationTimeout || remaining < egressInitialPopulationTimeout-time.Second {
					t.Fatal("population context has no fixed deadline")
				}
				return nil
			}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAttachOrderEgressFirstThenShim(t *testing.T) {
	config := &Config{
		ShimCfg: &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*NetworkSpec{
			"control": {Egress: "allowlist"},
			"ipc":     {Egress: "closed"},
		},
	}
	first, rest := attachOrder(Container{Name: "api", Networks: []string{"ipc", "control"}}, config)
	if first != "control" || len(rest) == 0 || rest[len(rest)-1] != "shim-net" {
		t.Fatalf("attach order = %q, %v", first, rest)
	}
}
