package egress

import (
	"context"
	"errors"
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
		nft: nftClient{apply: func(string) ([]byte, error) {
			applied = true
			return nil, nil
		}},
		interval: time.Minute,
	}

	err := engine.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), `network "control": DNS unavailable`) {
		t.Fatalf("Refresh() error = %v", err)
	}
	if applied {
		t.Fatal("resolution failure changed nft state")
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
		nft: nftClient{apply: func(script string) ([]byte, error) {
			want := "flush set inet tinfoil allow-alpha\n" +
				"add element inet tinfoil allow-alpha { 192.0.2.2, 192.0.2.1 }\n" +
				"flush set inet tinfoil allow-zeta\n"
			if script != want {
				t.Fatalf("nft script = %q, want %q", script, want)
			}
			return nil, nil
		}},
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
		resolve: func(context.Context, []string) ([]string, error) { return nil, nil },
		nft: nftClient{apply: func(string) ([]byte, error) {
			return []byte("permission denied"), errors.New("exit status 1")
		}},
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
		nft:      nftClient{apply: func(string) ([]byte, error) { return nil, nil }},
		interval: time.Minute,
	}

	if err := engine.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh() error = %v, want context cancellation", err)
	}
}
