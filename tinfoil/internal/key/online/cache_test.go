package online

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"tinfoil/internal/key"
)

type validationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *validationClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *validationClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
func cacheValidator(t *testing.T, handler http.HandlerFunc) (*Validator, *validationClock) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	v, err := NewValidator(server.URL)
	require.NoError(t, err)
	v.client = server.Client()
	clock := &validationClock{now: time.Date(2026, time.November, 5, 0, 0, 0, 0, time.UTC)}
	v.now = clock.Now
	return v, clock
}
func cacheRequest() key.Request {
	return key.Request{APIKey: "valid", Domain: "gpt-oss-120b.example.test", RequestedHost: "gpt-oss-120b.example.test", Path: "/v1/chat/completions"}
}

func TestValidationCacheScopesAndRejectsOtherKeys(t *testing.T) {
	var calls atomic.Int64
	v, _ := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request key.Request
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		w.Header().Set(validationCacheTTLHeader, "30000")
		if request.APIKey != "valid" {
			w.WriteHeader(http.StatusUnauthorized)
		}
		io.WriteString(w, "OK")
	})
	request := cacheRequest()
	require.NoError(t, v.Validate(request))
	require.NoError(t, v.Validate(request))
	require.EqualValues(t, 1, calls.Load())
	variants := []key.Request{request, request, request}
	variants[0].Domain = "other.example.test"
	variants[1].RequestedHost = "other.example.test"
	variants[2].Path = "/v1/responses"
	for _, variant := range variants {
		require.NoError(t, v.Validate(variant))
	}
	require.EqualValues(t, 4, calls.Load())
	request.APIKey = "invalid"
	require.Error(t, v.Validate(request))
	require.Error(t, v.Validate(request))
	require.EqualValues(t, 6, calls.Load())
}

func TestValidationCacheDeadlineDoesNotSlide(t *testing.T) {
	var calls atomic.Int64
	var revoked atomic.Bool
	v, clock := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(validationCacheTTLHeader, "30000")
		if revoked.Load() {
			w.WriteHeader(http.StatusUnauthorized)
		}
		io.WriteString(w, "OK")
	})
	request := cacheRequest()
	require.NoError(t, v.Validate(request))
	revoked.Store(true)
	clock.Advance(20 * time.Second)
	require.NoError(t, v.Validate(request))
	require.EqualValues(t, 1, calls.Load())
	clock.Advance(11 * time.Second)
	require.Error(t, v.Validate(request))
	require.Error(t, v.Validate(request))
	require.EqualValues(t, 3, calls.Load())
}

func TestValidationCacheExpiresBeforeOutageAndRecovers(t *testing.T) {
	var calls atomic.Int64
	var unavailable atomic.Bool
	v, clock := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(validationCacheTTLHeader, "30000")
		if unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		io.WriteString(w, "OK")
	})
	request := cacheRequest()
	require.NoError(t, v.Validate(request))
	unavailable.Store(true)
	clock.Advance(31 * time.Second)
	require.Error(t, v.Validate(request))
	require.EqualValues(t, 2, calls.Load())
	unavailable.Store(false)
	require.NoError(t, v.Validate(request))
	require.EqualValues(t, 3, calls.Load())
}

func TestValidationCacheHonorsShortValidityAndTransitTime(t *testing.T) {
	t.Run("earlier key expiry", func(t *testing.T) {
		var calls atomic.Int64
		var revoked atomic.Bool
		v, clock := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set(validationCacheTTLHeader, "1000")
			if revoked.Load() {
				w.WriteHeader(http.StatusUnauthorized)
			}
			io.WriteString(w, "OK")
		})
		request := cacheRequest()
		require.NoError(t, v.Validate(request))
		revoked.Store(true)
		clock.Advance(2 * time.Second)
		require.Error(t, v.Validate(request))
		require.EqualValues(t, 2, calls.Load())
	})
	t.Run("validity consumed in transit", func(t *testing.T) {
		var calls atomic.Int64
		var clock *validationClock
		v, c := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			clock.Advance(2 * time.Second)
			w.Header().Set(validationCacheTTLHeader, "1000")
			io.WriteString(w, "OK")
		})
		clock = c
		request := cacheRequest()
		require.NoError(t, v.Validate(request))
		require.NoError(t, v.Validate(request))
		require.EqualValues(t, 2, calls.Load())
	})
}

func TestValidationCacheRequiresBoundedUnambiguousMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		values    []string
		wantCalls int64
	}{
		{name: "legacy", wantCalls: 2},
		{name: "zero", values: []string{"0"}, wantCalls: 2},
		{name: "negative", values: []string{"-1"}, wantCalls: 2},
		{name: "invalid", values: []string{"one second"}, wantCalls: 2},
		{name: "too long", values: []string{"30001"}, wantCalls: 2},
		{name: "overflow", values: []string{"9223372036854775808"}, wantCalls: 2},
		{name: "duplicate", values: []string{"1000", "2000"}, wantCalls: 2},
		{name: "cacheable", values: []string{"30000"}, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			v, _ := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				for _, value := range tc.values {
					w.Header().Add(validationCacheTTLHeader, value)
				}
				io.WriteString(w, "OK")
			})
			require.NoError(t, v.Validate(cacheRequest()))
			require.NoError(t, v.Validate(cacheRequest()))
			require.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

func TestValidationCacheLeavesMetricsOnline(t *testing.T) {
	var calls atomic.Int64
	v, _ := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request key.Request
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		w.Header().Set(validationCacheTTLHeader, "30000")
		if request.Path == "/metrics" && request.APIKey != "admin" {
			w.WriteHeader(http.StatusForbidden)
		}
		io.WriteString(w, "OK")
	})
	request := cacheRequest()
	require.NoError(t, v.Validate(request))
	request.Path = "/metrics"
	require.Error(t, v.Validate(request))
	request.APIKey = "admin"
	require.NoError(t, v.Validate(request))
	require.NoError(t, v.Validate(request))
	require.EqualValues(t, 4, calls.Load())
}

func TestValidationCacheEvictsAndSupportsConcurrentHits(t *testing.T) {
	var calls atomic.Int64
	v, _ := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(validationCacheTTLHeader, "30000")
		io.WriteString(w, "OK")
	})
	v.cache.Resize(2)
	request := cacheRequest()
	require.NoError(t, v.Validate(request))
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := v.Validate(request); err != nil {
				t.Errorf("cached validation: %v", err)
			}
		}()
	}
	group.Wait()
	require.EqualValues(t, 1, calls.Load())
	for _, credential := range []string{"second", "third", "valid"} {
		r := request
		r.APIKey = credential
		require.NoError(t, v.Validate(r))
	}
	require.EqualValues(t, 4, calls.Load())
}
