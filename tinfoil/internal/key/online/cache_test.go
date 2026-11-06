package online

import (
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

func cacheValidator(t *testing.T, handler http.HandlerFunc) *Validator {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	v, err := NewValidator(server.URL)
	require.NoError(t, err)
	v.client = server.Client()
	v.client.Timeout = validationTimeout
	t.Cleanup(v.refreshes.Wait)
	v.now = func() time.Time { return time.Date(2026, time.November, 5, 0, 0, 0, 0, time.UTC) }
	return v
}
func cacheRequest() key.Request {
	return key.Request{APIKey: "valid", Domain: "gpt-oss-120b.example.test", RequestedHost: "gpt-oss-120b.example.test", Path: "/v1/chat/completions"}
}

func TestValidationCacheScopes(t *testing.T) {
	var calls atomic.Int64
	request := cacheRequest()
	v := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set(validationCacheExpiryHeader, validationCacheNoExpiry)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		io.WriteString(w, "OK")
	})
	require.NoError(t, v.Validate(request))
	variants := []key.Request{request, request, request, request}
	variants[0].APIKey = "other"
	variants[1].Domain = "other.example.test"
	variants[2].RequestedHost = "other.example.test"
	variants[3].Path = "/v1/responses"
	for _, variant := range variants {
		require.Error(t, v.Validate(variant))
	}
	require.EqualValues(t, 5, calls.Load())
}

func TestValidationCacheRechecksAndInvalidates(t *testing.T) {
	for _, failure := range []string{"denial", "HTTP failure", "transport failure", "permission withdrawn"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int64
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			v := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
				switch calls.Add(1) {
				case 1:
					w.Header().Set(validationCacheExpiryHeader, validationCacheNoExpiry)
				case 2:
					close(entered)
					<-release
					switch failure {
					case "denial":
						w.WriteHeader(http.StatusUnauthorized)
					case "HTTP failure":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "transport failure":
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						connection.Close()
						return
					}
				case 3:
					w.WriteHeader(http.StatusTooManyRequests)
				default:
					w.Header().Set(validationCacheExpiryHeader, validationCacheNoExpiry)
				}
				io.WriteString(w, "OK")
			})
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			request := cacheRequest()
			require.NoError(t, v.Validate(request))
			now := v.now()
			v.now = func() time.Time { return now.Add(24 * time.Hour) }
			require.NoError(t, v.Validate(request))
			<-entered
			var group sync.WaitGroup
			for range 20 {
				group.Go(func() {
					if err := v.Validate(request); err != nil {
						t.Errorf("cached admission: %v", err)
					}
				})
			}
			group.Wait()
			require.EqualValues(t, 2, calls.Load())
			once.Do(func() { close(release) })
			v.refreshes.Wait()
			require.Error(t, v.Validate(request))
			require.NoError(t, v.Validate(request))
			require.EqualValues(t, 4, calls.Load())
		})
	}
}

func TestValidationCacheHonorsHardExpiry(t *testing.T) {
	var calls atomic.Int64
	v := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(validationCacheExpiryHeader, "2026-11-05T00:00:01Z")
		io.WriteString(w, "OK")
	})
	request := cacheRequest()
	require.NoError(t, v.Validate(request))
	now := v.now()
	v.now = func() time.Time { return now.Add(2 * time.Second) }
	err := v.Validate(request)
	require.Error(t, err)
	require.EqualValues(t, 2, calls.Load())
	require.Equal(t, http.StatusUnauthorized, err.(*key.ValidationError).StatusCode)
}

func TestValidationCacheRequiresExplicitPermission(t *testing.T) {
	for _, tc := range []struct {
		name       string
		values     []string
		path       string
		optimistic bool
	}{
		{name: "absent"},
		{name: "invalid expiry", values: []string{"tomorrow"}},
		{name: "zero expiry", values: []string{"0001-01-01T00:00:00Z"}},
		{name: "duplicate", values: []string{"none", "none"}},
		{name: "no hard expiry", values: []string{"none"}, optimistic: true},
		{name: "future expiry", values: []string{"2026-11-06T00:00:00Z"}, optimistic: true},
		{name: "metrics", values: []string{"none"}, path: "/metrics"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			v := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				for _, value := range tc.values {
					w.Header().Add(validationCacheExpiryHeader, value)
				}
				if n > 1 {
					w.WriteHeader(http.StatusForbidden)
				}
				io.WriteString(w, "OK")
			})
			request := cacheRequest()
			if tc.path != "" {
				request.Path = tc.path
			}
			require.NoError(t, v.Validate(request))
			err := v.Validate(request)
			if tc.optimistic {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			v.refreshes.Wait()
			require.EqualValues(t, 2, calls.Load())
		})
	}
}

func TestValidationCacheLateSuccessCannotRestoreDeniedAllowance(t *testing.T) {
	var calls atomic.Int64
	arrived := make(chan int64, 2)
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	var firstOnce, secondOnce sync.Once
	v := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch n {
		case 1:
			arrived <- n
			<-releaseFirst
			w.Header().Set(validationCacheExpiryHeader, validationCacheNoExpiry)
		case 2:
			arrived <- n
			<-releaseSecond
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
		io.WriteString(w, "OK")
	})
	t.Cleanup(func() { firstOnce.Do(func() { close(releaseFirst) }); secondOnce.Do(func() { close(releaseSecond) }) })
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- v.Validate(cacheRequest()) }()
	require.EqualValues(t, 1, <-arrived)
	go func() { second <- v.Validate(cacheRequest()) }()
	require.EqualValues(t, 2, <-arrived)
	secondOnce.Do(func() { close(releaseSecond) })
	require.Error(t, <-second)
	firstOnce.Do(func() { close(releaseFirst) })
	require.NoError(t, <-first)
	require.Error(t, v.Validate(cacheRequest()))
	require.EqualValues(t, 3, calls.Load())
}

func TestValidationCacheEvictsOldEntries(t *testing.T) {
	var calls atomic.Int64
	v := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 2 {
			w.WriteHeader(http.StatusUnauthorized)
		}
		w.Header().Set(validationCacheExpiryHeader, validationCacheNoExpiry)
		io.WriteString(w, "OK")
	})
	v.cache.Resize(1)
	request := cacheRequest()
	require.NoError(t, v.Validate(request))
	request.APIKey = "second"
	require.NoError(t, v.Validate(request))
	request.APIKey = "valid"
	require.Error(t, v.Validate(request))
	require.EqualValues(t, 3, calls.Load())
}

func TestValidationCacheSaturationFallsBackToOnline(t *testing.T) {
	var calls atomic.Int64
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	v := cacheValidator(t, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 3 {
			close(entered)
			<-release
		}
		if n == 4 {
			w.WriteHeader(http.StatusForbidden)
		}
		w.Header().Set(validationCacheExpiryHeader, validationCacheNoExpiry)
		io.WriteString(w, "OK")
	})
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	v.background = make(chan struct{}, 1)
	first := cacheRequest()
	second := first
	second.APIKey = "second"
	require.NoError(t, v.Validate(first))
	require.NoError(t, v.Validate(second))
	require.NoError(t, v.Validate(first))
	<-entered
	require.Error(t, v.Validate(second))
	once.Do(func() { close(release) })
	v.refreshes.Wait()
	require.EqualValues(t, 4, calls.Load())
}
