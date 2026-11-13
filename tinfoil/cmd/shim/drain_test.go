package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
)

func startDrainServer(t *testing.T, handler http.Handler) (string, context.CancelFunc, <-chan error) {
	return startShutdownServer(t, handler, &shimconfig.Config{DrainConnections: true, DrainTimeout: 5 * time.Second})
}

func startShutdownServer(t *testing.T, handler http.Handler, policy *shimconfig.Config) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	previous := connectionDrain.Swap(policy)
	t.Cleanup(func() { connectionDrain.Store(previous) })
	cert, err := generateEphemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	// Reserve a local address for the real ListenAndServeTLS path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{Addr: addr, Handler: handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	done := make(chan error, 1)
	go func() { done <- serveUntilShutdown(ctx, srv) }()
	t.Cleanup(func() { cancel(); srv.Close() })

	// Wait for both guests to accept TLS before testing cutover. Application
	// requests below must still fail the test on any connection error.
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("server exited during startup: %v", err)
		default:
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true})
		if err == nil {
			conn.Close()
			return addr, cancel, done
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestShutdownPreservesStreamAndReconnects(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			finish := make(chan struct{})
			defer close(finish)
			start := func(label string) (string, context.CancelFunc, <-chan error) {
				t.Helper()
				return startDrainServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/stream" {
						io.WriteString(w, "begin\n")
						w.(http.Flusher).Flush()
						<-finish
						io.WriteString(w, "complete\n")
						return
					}
					io.WriteString(w, label)
				}))
			}
			oldAddr, drain, drained := start("old")
			newAddr, _, _ := start("new")
			var target atomic.Value
			target.Store(oldAddr)
			tr := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", target.Load().(string))
				}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
			stream, err := client.Get("https://drain.test/stream")
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Body.Close()
			if (stream.ProtoMajor == 2) != h2 {
				t.Fatalf("protocol = %s", stream.Proto)
			}
			reader := bufio.NewReader(stream.Body)
			if line, err := reader.ReadString('\n'); err != nil || line != "begin\n" {
				t.Fatalf("stream start = %q, %v", line, err)
			}
			// HTTP/1 needs another connection; HTTP/2 reuses the streaming one.
			get := func() string {
				t.Helper()
				resp, err := client.Get("https://drain.test/")
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			if got := get(); got != "old" {
				t.Fatalf("before drain = %q", got)
			}
			target.Store(newAddr)
			drain()
			deadline := time.Now().Add(3 * time.Second)
			for get() != "new" {
				if time.Now().After(deadline) {
					t.Fatal("client did not reconnect while stream was active")
				}
				time.Sleep(time.Millisecond)
			}
			select {
			case err := <-drained:
				t.Fatalf("shutdown returned before stream finished: %v", err)
			default:
			}
			finish <- struct{}{}
			if body, err := io.ReadAll(reader); err != nil || string(body) != "complete\n" {
				t.Fatalf("stream tail = %q, %v", body, err)
			}
			select {
			case err := <-drained:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown did not finish after stream completed")
			}
		})
	}
}

func TestShutdownWaitsForHijackedStream(t *testing.T) {
	finish := make(chan struct{})
	defer close(finish)
	addr, cancel, done := startDrainServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		rw.Flush()
		<-finish
		rw.WriteString("complete\n")
		rw.Flush()
	}))
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 101 {
		t.Fatalf("upgrade status = %s", resp.Status)
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("shutdown interrupted upgraded stream: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	finish <- struct{}{}
	if b, err := io.ReadAll(resp.Body); err != nil || string(b) != "complete\n" {
		t.Fatalf("upgraded stream tail = %q, %v", b, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

const (
	shutdownChildEnv            = "TINFOIL_DRAIN_TEST_CHILD"
	shutdownProtocolEnv         = "TINFOIL_DRAIN_TEST_PROTOCOL"
	shutdownEnabledEnv          = "TINFOIL_DRAIN_TEST_ENABLED"
	shutdownTestDrainTimeout    = 20 * time.Millisecond
	shutdownTestDisabledTimeout = 5 * time.Second
	shutdownTestWait            = 3 * time.Second
	shutdownTestImmediateWait   = time.Second
	shutdownTestProcessLifetime = 10 * time.Second
)

func TestShutdownClosesWithoutDrainOrAtConfiguredTimeout(t *testing.T) {
	if os.Getenv(shutdownChildEnv) == "1" {
		runShutdownTestServer(t)
		return
	}
	for _, protocol := range []string{"http1", "http2", "hijacked"} {
		for _, enabled := range []bool{false, true} {
			t.Run(protocol+"/"+strconv.FormatBool(enabled), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), shutdownTestProcessLifetime)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShutdownClosesWithoutDrainOrAtConfiguredTimeout$")
				command.Env = append(os.Environ(), shutdownChildEnv+"=1", shutdownProtocolEnv+"="+protocol, shutdownEnabledEnv+"="+strconv.FormatBool(enabled))
				var childLog bytes.Buffer
				command.Stderr = &childLog
				output, err := command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				exited := make(chan error, 1)
				go func() { exited <- command.Wait() }()
				waited := false
				t.Cleanup(func() {
					if !waited {
						command.Process.Kill()
						<-exited
					}
				})
				address, err := bufio.NewReader(output).ReadString('\n')
				if err != nil {
					t.Fatalf("child startup: %v", err)
				}
				transport := &http.Transport{ForceAttemptHTTP2: protocol == "http2", TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: shutdownTestProcessLifetime}
				response, err := client.Get("https://" + strings.TrimSpace(address))
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if protocol == "http2" && response.ProtoMajor != 2 || protocol == "hijacked" && response.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("unexpected response: %s %s", response.Proto, response.Status)
				}
				reader := bufio.NewReader(response.Body)
				if line, err := reader.ReadString('\n'); err != nil || line != "begin\n" {
					t.Fatalf("stream start = %q, %v", line, err)
				}
				start := time.Now()
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				wait := shutdownTestWait
				if !enabled {
					wait = shutdownTestImmediateWait
				}
				select {
				case err := <-exited:
					waited = true
					if err != nil {
						t.Fatalf("child shutdown: %v\n%s", err, childLog.String())
					}
					if enabled && time.Since(start) < shutdownTestDrainTimeout {
						t.Fatal("shutdown ended before the configured drain interval")
					}
				case <-time.After(wait):
					t.Fatal("shutdown waited beyond the configured drain policy")
				}
				type readResult struct {
					body []byte
					err  error
				}
				closed := make(chan readResult, 1)
				go func() {
					body, err := io.ReadAll(reader)
					closed <- readResult{body: body, err: err}
				}()
				select {
				case result := <-closed:
					if len(result.body) != 0 {
						t.Fatalf("blocked handler produced unexpected bytes: %q", result.body)
					}
					var networkError net.Error
					if errors.As(result.err, &networkError) && networkError.Timeout() {
						t.Fatalf("connection ended at the client's timeout: %v", result.err)
					}
				case <-time.After(shutdownTestImmediateWait):
					t.Fatal("shutdown left the response connection open")
				}
			})
		}
	}
}

func runShutdownTestServer(t *testing.T) {
	enabled, err := strconv.ParseBool(os.Getenv(shutdownEnabledEnv))
	if err != nil {
		t.Fatal(err)
	}
	timeout := shutdownTestDisabledTimeout
	if enabled {
		timeout = shutdownTestDrainTimeout
	}
	connectionDrain.Store(&shimconfig.Config{DrainConnections: enabled, DrainTimeout: timeout})
	certificate, err := generateEphemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finish := make(chan struct{})
	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv(shutdownProtocolEnv) == "hijacked" {
			connection, writer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer connection.Close()
			writer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\nbegin\n")
			writer.Flush()
		} else {
			io.WriteString(w, "begin\n")
			w.(http.Flusher).Flush()
		}
		<-finish
	})}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	fmt.Println(listener.Addr().String())
	if err := serveHTTPUntilShutdown(ctx, server, func() error { return server.ServeTLS(listener, "", "") }, workloadDrain); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
