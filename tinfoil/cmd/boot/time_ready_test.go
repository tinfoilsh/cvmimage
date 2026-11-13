package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTimeReadinessRequiresExplicitQuorumAcknowledgment(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusNotFound, http.StatusInternalServerError} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Error("time readiness did not use POST")
			}
			w.WriteHeader(status)
		}))
		client := server.Client()
		client.Transport = &readinessTransport{target: server.URL, base: client.Transport}
		err := armTimeQuorum(context.Background(), client)
		server.Close()
		if (err == nil) != (status == http.StatusNoContent) {
			t.Fatalf("HTTP %d accepted=%t", status, err == nil)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := armTimeQuorum(ctx, http.DefaultClient); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled readiness returned %v", err)
	}
}

func TestTimeReadinessRetriesUnavailableQuorum(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := server.Client()
	client.Transport = &readinessTransport{target: server.URL, base: client.Transport}
	ctx, cancel := context.WithTimeout(context.Background(), 2*clockWaitInterval)
	defer cancel()
	if err := armTimeQuorum(ctx, client); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("readiness attempts=%d, want 2", attempts.Load())
	}
}

type readinessTransport struct {
	target string
	base   http.RoundTripper
}

func (transport *readinessTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	redirected := request.Clone(request.Context())
	target, err := http.NewRequestWithContext(request.Context(), request.Method, transport.target+request.URL.Path, nil)
	if err != nil {
		return nil, err
	}
	redirected.URL = target.URL
	return transport.base.RoundTrip(redirected)
}
