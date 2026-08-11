package attestationmaterial

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

type fetchFunc func(context.Context, wire.Request) (wire.Response, error)

func (f fetchFunc) Fetch(ctx context.Context, request wire.Request) (wire.Response, error) {
	return f(ctx, request)
}

func TestCacheFetchesLazily(t *testing.T) {
	now := time.Now()
	calls := 0
	cache := NewCache(wire.Request{Repo: "repo", Platform: "sev-snp"}, fetchFunc(func(_ context.Context, _ wire.Request) (wire.Response, error) {
		calls++
		return response(now.Add(48*time.Hour), "first"), nil
	}))
	cache.now = func() time.Time { return now }

	got, err := cache.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(got) != 1 || got[0].ID != "first" {
		t.Fatalf("calls=%d collateral=%v", calls, got)
	}
	got[0].Data[0] = 'X'
	got, err = cache.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(got[0].Data) != `{"value":true}` {
		t.Fatalf("cache was not reused safely: calls=%d collateral=%s", calls, got[0].Data)
	}
}

func TestCacheRefreshesOnceWhenDue(t *testing.T) {
	now := time.Now()
	started := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	cache := NewCache(wire.Request{Repo: "repo", Platform: "tdx"}, fetchFunc(func(_ context.Context, _ wire.Request) (wire.Response, error) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 2 {
			close(started)
			<-release
			close(completed)
		}
		return response(now.Add(48*time.Hour), "entry"), nil
	}))
	cache.now = func() time.Time { return now }
	if _, err := cache.Current(context.Background()); err != nil {
		t.Fatal(err)
	}

	now = now.Add(24 * time.Hour)
	for range 5 {
		if _, err := cache.Current(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	<-started
	mu.Lock()
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2", calls)
	}
	mu.Unlock()
	close(release)
	<-completed
}

func TestCacheFailsClosedAfterExpiry(t *testing.T) {
	now := time.Now()
	calls := 0
	cache := NewCache(wire.Request{Repo: "repo", Platform: "sev-snp"}, fetchFunc(func(_ context.Context, _ wire.Request) (wire.Response, error) {
		calls++
		if calls > 1 {
			return wire.Response{}, errors.New("ATC unavailable")
		}
		return response(now.Add(time.Hour), "entry"), nil
	}))
	cache.now = func() time.Time { return now }
	if _, err := cache.Current(context.Background()); err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Hour)
	if _, err := cache.Current(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Current() error = %v, want ErrUnavailable", err)
	}
	if _, err := cache.Current(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Current() cooldown error = %v, want ErrUnavailable", err)
	}
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2", calls)
	}
}

func response(expiresAt time.Time, id string) wire.Response {
	return wire.Response{
		Format:    wire.FormatV2,
		ExpiresAt: expiresAt,
		Collateral: []envelope.CollateralEntry{{
			ID:   id,
			Data: []byte(`{"value":true}`),
		}},
	}
}
