package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

const localAttestationTestTimeout = 5 * time.Second

var localAttestationTestQuery = localAttestationPath + "?nonce=" + strings.Repeat("ab", envelope.NonceSize)

func inheritedTestAttestationListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attestation.sock")
	original, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	original.SetUnlinkOnClose(false)
	defer original.Close()
	file, err := original.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := inheritedAttestationListener(fd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("inherited descriptor remains open: %v", err)
	}
	return listener, path
}

func startLocalAttestationTestServer(t *testing.T, handler http.Handler) (*http.Client, *http.Server, context.CancelFunc, <-chan error, string) {
	t.Helper()
	listener, path := inheritedTestAttestationListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	server := &http.Server{Handler: handler, ReadHeaderTimeout: shimReadHeaderTimeout}
	done := make(chan error, 1)
	go func() { done <- serveLocalAttestation(ctx, server, listener) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	client := &http.Client{Transport: transport, Timeout: localAttestationTestTimeout}
	t.Cleanup(func() {
		cancel()
		server.Close()
		transport.CloseIdleConnections()
	})
	return client, server, cancel, done, path
}

func localAttestationTestRequest(t *testing.T, client *http.Client, method, target, body string) (*http.Response, string) {
	t.Helper()
	request, err := http.NewRequest(method, "http://shim"+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(data)
}

func TestLocalAttestationRejectsOtherRequests(t *testing.T) {
	var forwarded atomic.Int32
	handler := newLocalAttestationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		io.WriteString(w, r.URL.Query().Get("nonce"))
	}))
	client, _, _, _, _ := startLocalAttestationTestServer(t, handler)
	for _, test := range []struct {
		name, method, target, body string
		status                     int
	}{
		{name: "missing nonce", method: http.MethodGet, target: localAttestationPath, status: http.StatusBadRequest},
		{name: "empty nonce", method: http.MethodGet, target: localAttestationPath + "?nonce=", status: http.StatusBadRequest},
		{name: "short nonce", method: http.MethodGet, target: localAttestationPath + "?nonce=ab", status: http.StatusBadRequest},
		{name: "long nonce", method: http.MethodGet, target: localAttestationTestQuery + "ab", status: http.StatusBadRequest},
		{name: "invalid hex", method: http.MethodGet, target: localAttestationPath + "?nonce=" + strings.Repeat("zz", envelope.NonceSize), status: http.StatusBadRequest},
		{name: "duplicate nonce", method: http.MethodGet, target: localAttestationTestQuery + "&nonce=ab", status: http.StatusBadRequest},
		{name: "extra query", method: http.MethodGet, target: localAttestationTestQuery + "&key=ab", status: http.StatusBadRequest},
		{name: "malformed query", method: http.MethodGet, target: localAttestationTestQuery + "&%zz=ab", status: http.StatusBadRequest},
		{name: "body", method: http.MethodGet, target: localAttestationTestQuery, body: "payload", status: http.StatusBadRequest},
		{name: "post", method: http.MethodPost, target: localAttestationTestQuery, status: http.StatusMethodNotAllowed},
		{name: "connect", method: http.MethodConnect, target: localAttestationTestQuery, status: http.StatusMethodNotAllowed},
		{name: "proxy", method: http.MethodGet, target: "/v1/chat/completions", status: http.StatusNotFound},
		{name: "observability", method: http.MethodGet, target: "/.well-known/tinfoil-containers", status: http.StatusNotFound},
		{name: "trailing slash", method: http.MethodGet, target: localAttestationPath + "/", status: http.StatusNotFound},
		{name: "encoded path", method: http.MethodGet, target: "/.well-known/%74infoil-attestation", status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, body := localAttestationTestRequest(t, client, test.method, test.target, test.body)
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d: %s", response.StatusCode, test.status, body)
			}
		})
	}
	if got := forwarded.Load(); got != 0 {
		t.Fatalf("forwarded %d rejected requests", got)
	}
	response, body := localAttestationTestRequest(t, client, http.MethodGet, localAttestationTestQuery, "")
	if response.StatusCode != http.StatusOK || body != strings.Repeat("ab", envelope.NonceSize) {
		t.Fatalf("valid request = %d %q", response.StatusCode, body)
	}
}

func TestLocalAttestationAllowsConcurrentRequests(t *testing.T) {
	release := make(chan struct{})
	releaseFirst := sync.OnceFunc(func() { close(release) })
	defer releaseFirst()
	var calls atomic.Int32
	handler := newLocalAttestationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-release
		}
		io.WriteString(w, r.URL.Query().Get("nonce"))
	}))
	client, _, _, _, _ := startLocalAttestationTestServer(t, handler)
	first, err := client.Get("http://shim" + localAttestationTestQuery)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	for _, nonce := range []string{strings.Repeat("cd", envelope.NonceSize), strings.Repeat("ef", envelope.NonceSize)} {
		response, body := localAttestationTestRequest(t, client, http.MethodGet, localAttestationPath+"?nonce="+nonce, "")
		if response.StatusCode != http.StatusOK || body != nonce {
			t.Fatalf("concurrent request = %d %q, want %q", response.StatusCode, body, nonce)
		}
	}
	releaseFirst()
	body, err := io.ReadAll(first.Body)
	if err != nil || first.StatusCode != http.StatusOK || string(body) != strings.Repeat("ab", envelope.NonceSize) {
		t.Fatalf("first request = %d %q, %v", first.StatusCode, body, err)
	}
}

func TestLocalAttestationFollowsReadinessAndPreservesSocket(t *testing.T) {
	var current atomic.Value
	current.Store(http.HandlerFunc(bootStagesHandler().ServeHTTP))
	handler := newLocalAttestationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current.Load().(http.Handler).ServeHTTP(w, r)
	}))
	client, _, cancel, done, path := startLocalAttestationTestServer(t, handler)
	response, _ := localAttestationTestRequest(t, client, http.MethodGet, localAttestationTestQuery, "")
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("boot request status = %d", response.StatusCode)
	}
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ready := NewObservabilityServer(&legacy.Document{Format: legacy.DummyV2}, tinfoilattestation.BodyV2{}, 0,
		id, nil, errorCollateralSource{}, &config.Config{}, &config.ExternalConfig{})
	current.Store(http.HandlerFunc(ready.ServeHTTP))
	response, body := localAttestationTestRequest(t, client, http.MethodGet, localAttestationTestQuery, "")
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, errMsgCollateralUnavailable) {
		t.Fatalf("ready request did not reach fresh attestation: %d %s", response.StatusCode, body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(localAttestationTestTimeout):
		t.Fatal("local server did not stop")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("inherited socket was removed on shutdown: %v", err)
	}
}

func TestLocalAttestationShutdownWaitsForQuote(t *testing.T) {
	release := make(chan struct{})
	releaseQuote := sync.OnceFunc(func() { close(release) })
	defer releaseQuote()
	handler := newLocalAttestationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "pending\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "complete\n")
	}))
	client, server, cancel, done, _ := startLocalAttestationTestServer(t, handler)
	stopping := make(chan struct{})
	server.RegisterOnShutdown(func() { close(stopping) })
	response, err := client.Get("http://shim" + localAttestationTestQuery)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	cancel()
	select {
	case <-stopping:
	case <-time.After(localAttestationTestTimeout):
		t.Fatal("shutdown did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("shutdown returned before quote completed: %v", err)
	default:
	}
	releaseQuote()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "pending\ncomplete\n" {
		t.Fatalf("quote response = %q, %v", data, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(localAttestationTestTimeout):
		t.Fatal("shutdown did not finish after quote completed")
	}
}

func TestLocalAttestationFailureStopsPublicServer(t *testing.T) {
	listener, _ := inheritedTestAttestationListener(t)
	listener.Close()
	cert, err := generateEphemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Addr:      "127.0.0.1:0",
		Handler:   bootStagesHandler(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	t.Cleanup(func() { server.Close() })
	done := make(chan error, 1)
	go func() { done <- serveWithAttestation(context.Background(), server, listener) }()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("listener failure = %v", err)
		}
	case <-time.After(localAttestationTestTimeout):
		t.Fatal("public server continued after local listener failure")
	}
}

func TestInheritedAttestationListenerIsOptional(t *testing.T) {
	listener, err := inheritedAttestationListener(noAttestationFD)
	if listener != nil || err != nil {
		t.Fatalf("disabled listener = %v, %v", listener, err)
	}
	if _, err := inheritedAttestationListener(noAttestationFD - 1); err == nil {
		t.Fatal("invalid descriptor was accepted")
	}
}
