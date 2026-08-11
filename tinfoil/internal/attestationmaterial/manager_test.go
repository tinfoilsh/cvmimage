package attestationmaterial

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

type fakeFetcher struct {
	response wire.Response
	err      error
	called   chan struct{}
}

func (f *fakeFetcher) Fetch(context.Context, wire.Request) (wire.Response, error) {
	if f.called != nil {
		select {
		case f.called <- struct{}{}:
		default:
		}
	}
	return f.response, f.err
}

func managedRequest() wire.Request {
	return wire.Request{Repo: "tinfoilsh/example", Platform: "sev-snp", QuoteBase64: "cXVvdGU="}
}

func responseWith(expiry time.Time, id string) wire.Response {
	return wire.Response{
		Format:    wire.FormatV2,
		ExpiresAt: expiry,
		Collateral: []envelope.CollateralEntry{
			{ID: id, Role: "endorsement", Format: "example/v1", Data: json.RawMessage(`{}`)},
		},
	}
}

func TestManagerCurrentRejectsExpiredCollateral(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(responseWith(now, "old"), managedRequest(), &fakeFetcher{}, "")
	manager.now = func() time.Time { return now }

	if _, err := manager.Current(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Current error = %v, want ErrUnavailable", err)
	}
}

func TestManagerCurrentReturnsCopy(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(responseWith(now.Add(time.Hour), "current"), managedRequest(), &fakeFetcher{}, "")
	manager.now = func() time.Time { return now }

	first, err := manager.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	first[0].ID = "mutated"
	second, err := manager.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if second[0].ID != "current" {
		t.Fatalf("stored collateral was mutated: %q", second[0].ID)
	}
}

func TestManagerAllowsUnmanagedEmptyCollateral(t *testing.T) {
	manager := NewManager(wire.Response{Format: wire.FormatV2}, wire.Request{}, nil, "")
	got, err := manager.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Current returned %d entries", len(got))
	}
}

func TestManagerRefreshReplacesAndPersistsCollateral(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "attestation-material.json")
	fetcher := &fakeFetcher{response: responseWith(now.Add(24*time.Hour), "new")}
	manager := NewManager(responseWith(now.Add(time.Hour), "old"), managedRequest(), fetcher, path)
	manager.now = func() time.Time { return now }

	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	current, err := manager.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if current[0].ID != "new" {
		t.Fatalf("current collateral id = %q", current[0].ID)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	persisted, err := ParseResponse(data)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if persisted.Collateral[0].ID != "new" {
		t.Fatalf("persisted collateral id = %q", persisted.Collateral[0].ID)
	}
}

func TestManagerRefreshFailureKeepsCurrentCollateral(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(responseWith(now.Add(time.Hour), "old"), managedRequest(), &fakeFetcher{err: errors.New("ATC unavailable")}, "")
	manager.now = func() time.Time { return now }

	if err := manager.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded")
	}
	current, err := manager.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if current[0].ID != "old" {
		t.Fatalf("current collateral id = %q", current[0].ID)
	}
}

func TestManagerSchedulesBeforeExpiryWithJitter(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(responseWith(now.Add(24*time.Hour), "old"), managedRequest(), &fakeFetcher{}, "")
	manager.now = func() time.Time { return now }
	manager.jitter = func(time.Duration) time.Duration { return time.Hour }

	if got, want := manager.nextRefreshDelay(), 19*time.Hour; got != want {
		t.Fatalf("nextRefreshDelay = %s, want %s", got, want)
	}
}

func TestManagerUsesHalfLifeForShortTTL(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(responseWith(now.Add(time.Hour), "old"), managedRequest(), &fakeFetcher{}, "")
	manager.now = func() time.Time { return now }
	manager.jitter = func(time.Duration) time.Duration { return time.Hour }

	if got, want := manager.nextRefreshDelay(), 30*time.Minute; got != want {
		t.Fatalf("nextRefreshDelay = %s, want %s", got, want)
	}
}

func TestManagerCapsRefreshInterval(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager := NewManager(responseWith(now.Add(7*24*time.Hour), "old"), managedRequest(), &fakeFetcher{}, "")
	manager.now = func() time.Time { return now }
	manager.jitter = func(time.Duration) time.Duration { return 0 }

	if got, want := manager.nextRefreshDelay(), 24*time.Hour; got != want {
		t.Fatalf("nextRefreshDelay = %s, want %s", got, want)
	}
}

func TestManagerRunRefreshesAutomatically(t *testing.T) {
	now := time.Now()
	called := make(chan struct{}, 1)
	fetcher := &fakeFetcher{response: responseWith(now.Add(time.Hour), "new"), called: called}
	manager := NewManager(responseWith(now.Add(40*time.Millisecond), "old"), managedRequest(), fetcher, "")
	manager.refreshBefore = 30 * time.Millisecond
	manager.jitter = func(time.Duration) time.Duration { return 0 }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Run(ctx)

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("manager did not refresh")
	}
}
