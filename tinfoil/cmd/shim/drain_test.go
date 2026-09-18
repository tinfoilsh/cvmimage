package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestShutdownPreservesStreamAndReconnects(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			cert, err := generateEphemeralCert()
			if err != nil {
				t.Fatal(err)
			}
			finish := make(chan struct{})
			defer close(finish)
			start := func(label string) (string, context.CancelFunc, <-chan error) {
				t.Helper()
				// Reserve a local address for the real ListenAndServeTLS path.
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr := ln.Addr().String()
				ln.Close()
				ctx, cancel := context.WithCancel(context.Background())
				srv := &http.Server{Addr: addr, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/stream" {
							io.WriteString(w, "begin\n")
							w.(http.Flusher).Flush()
							<-finish
							io.WriteString(w, "complete\n")
							return
						}
						io.WriteString(w, label)
					})}
				done := make(chan error, 1)
				go func() { done <- serveUntilShutdown(ctx, srv) }()
				t.Cleanup(func() { cancel(); srv.Close() })
				return addr, cancel, done
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
			var stream *http.Response
			deadline := time.Now().Add(5 * time.Second)
			for {
				stream, err = client.Get("https://drain.test/stream")
				if err == nil || time.Now().After(deadline) {
					break
				}
				time.Sleep(time.Millisecond)
			}
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
			deadline = time.Now().Add(3 * time.Second)
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
	cert, err := generateEphemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	finish := make(chan struct{})
	defer close(finish)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &http.Server{Addr: addr, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		})}
	defer srv.Close()
	done := make(chan error, 1)
	go func() { done <- serveUntilShutdown(ctx, srv) }()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer client.CloseIdleConnections()
	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err = client.Get("https://" + addr)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
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
