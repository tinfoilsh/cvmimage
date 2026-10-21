package attestationmaterial

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
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
	got[0].Subjects[0] = "changed"
	got, err = cache.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(got[0].Data) != `{"value":true}` || got[0].Subjects[0] != "subject" {
		t.Fatalf("cache was not reused safely: calls=%d collateral=%s", calls, got[0].Data)
	}
}

func TestCacheRefreshesOnceWhenDue(t *testing.T) {
	for _, test := range []struct {
		name         string
		lifetime     time.Duration
		refreshAfter time.Duration
	}{
		{name: "long-lived collateral", lifetime: 24 * time.Hour, refreshAfter: time.Minute},
		{name: "near expiry", lifetime: 20 * time.Second, refreshAfter: 10 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				calls := 0
				cache := NewCache(wire.Request{Repo: "repo", Platform: "tdx"}, fetchFunc(func(_ context.Context, _ wire.Request) (wire.Response, error) {
					calls++
					if calls == 1 {
						return response(time.Now().Add(test.lifetime), "old"), nil
					}
					<-release
					return response(time.Now().Add(test.lifetime), "new"), nil
				}))
				if _, err := cache.Current(context.Background()); err != nil {
					t.Fatal(err)
				}

				time.Sleep(test.refreshAfter - time.Nanosecond)
				got, err := cache.Current(context.Background())
				synctest.Wait()
				if err != nil || len(got) != 1 || got[0].ID != "old" || calls != 1 {
					t.Fatalf("before refresh: collateral=%v error=%v calls=%d", got, err, calls)
				}

				time.Sleep(time.Nanosecond)
				for range 5 {
					go func() {
						got, err := cache.Current(context.Background())
						if err != nil || len(got) != 1 || got[0].ID != "old" {
							t.Errorf("during refresh: collateral=%v error=%v", got, err)
						}
					}()
				}
				synctest.Wait()
				if calls != 2 {
					t.Fatalf("fetch calls = %d, want 2", calls)
				}
				close(release)
				synctest.Wait()
				got, err = cache.Current(context.Background())
				if err != nil || len(got) != 1 || got[0].ID != "new" || calls != 2 {
					t.Fatalf("after refresh: collateral=%v error=%v calls=%d", got, err, calls)
				}
			})
		})
	}
}

func TestCacheKeepsValidCollateralWhenRefreshFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		cache := NewCache(wire.Request{Repo: "repo", Platform: "tdx"}, fetchFunc(func(_ context.Context, _ wire.Request) (wire.Response, error) {
			calls++
			switch calls {
			case 1:
				return response(time.Now().Add(24*time.Hour), "old"), nil
			case 2:
				return wire.Response{}, errors.New("ATC unavailable")
			default:
				return response(time.Now().Add(24*time.Hour), "new"), nil
			}
		}))
		if _, err := cache.Current(context.Background()); err != nil {
			t.Fatal(err)
		}

		time.Sleep(time.Minute)
		for range 5 {
			got, err := cache.Current(context.Background())
			if err != nil || len(got) != 1 || got[0].ID != "old" {
				t.Fatalf("failed refresh: collateral=%v error=%v", got, err)
			}
			synctest.Wait()
		}
		if calls != 2 {
			t.Fatalf("fetch calls = %d, want 2", calls)
		}

		time.Sleep(time.Minute)
		if _, err := cache.Current(context.Background()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		got, err := cache.Current(context.Background())
		if err != nil || len(got) != 1 || got[0].ID != "new" || calls != 3 {
			t.Fatalf("after retry: collateral=%v error=%v calls=%d", got, err, calls)
		}
	})
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
		Collateral: []collateral.Entry{{
			ID:       id,
			Subjects: []string{"subject"},
			Data:     []byte(`{"value":true}`),
		}},
	}
}
