package egress

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRefreshFailsClosedBeforeNftOnResolutionError(t *testing.T) {
	applied := false
	engine := &Engine{
		config: &config{Networks: map[string]network{
			"control": {Allow: []string{"api.example"}},
		}},
		resolve: func(context.Context, []string) ([]string, error) {
			return nil, errors.New("DNS unavailable")
		},
		apply: func(context.Context, map[string][]netip.Addr) error {
			applied = true
			return nil
		},
		interval: time.Minute,
	}

	err := engine.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), `network "control": DNS unavailable`) {
		t.Fatalf("Refresh() error = %v", err)
	}
	if applied {
		t.Fatal("resolution failure changed netfilter state")
	}
}

func TestRefreshReplacesAllSetsInOneDeterministicTransaction(t *testing.T) {
	engine := &Engine{
		config: &config{Networks: map[string]network{
			"zeta":  {Allow: nil},
			"alpha": {Allow: []string{"api.example"}},
		}},
		resolve: func(_ context.Context, domains []string) ([]string, error) {
			if len(domains) == 0 {
				return nil, nil
			}
			return []string{"192.0.2.2", "192.0.2.1"}, nil
		},
		apply: func(_ context.Context, sets map[string][]netip.Addr) error {
			want := map[string][]netip.Addr{
				"allow-alpha": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
				"allow-zeta":  {},
			}
			if !reflect.DeepEqual(sets, want) {
				t.Fatalf("sets = %#v, want %#v", sets, want)
			}
			return nil
		},
		interval: time.Minute,
	}

	if err := engine.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
}

func TestRefreshPropagatesNftFailure(t *testing.T) {
	engine := &Engine{
		config: &config{Networks: map[string]network{
			"control": {Allow: nil},
		}},
		resolve:  func(context.Context, []string) ([]string, error) { return nil, nil },
		apply:    func(context.Context, map[string][]netip.Addr) error { return errors.New("permission denied") },
		interval: time.Minute,
	}

	err := engine.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Refresh() error = %v", err)
	}
}

func TestRefreshThreadsCancellationIntoResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine := &Engine{
		config: &config{Networks: map[string]network{
			"control": {Allow: []string{"api.example"}},
		}},
		resolve: func(ctx context.Context, _ []string) ([]string, error) {
			return nil, ctx.Err()
		},
		apply:    func(context.Context, map[string][]netip.Addr) error { return nil },
		interval: time.Minute,
	}

	if err := engine.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh() error = %v, want context cancellation", err)
	}
}
