package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"golang.org/x/net/http2"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
)

const tunnelTestDomain = "cvm.example"

func writeRuntimeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime-config.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPublishedPorts(t *testing.T) {
	targets, err := publishedPorts(writeRuntimeConfig(t, "containers:\n  - name: sandbox\n    ports: ['2300:25565', '2301:8080']\n    tunnel-ports: [2300, 2301]\n  - name: quiet\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(targets) != 2 || !targets["2300"] || !targets["2301"] {
		t.Fatalf("targets = %v", targets)
	}
	if _, err := publishedPorts(writeRuntimeConfig(t, "containers:\n  - name: sandbox\n    ports: ['25565']\n")); err == nil {
		t.Fatal("expected an error for a port without a mapping")
	}
}

func echoListener(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func tunnelServer(t *testing.T, port int, enabled bool) *httptest.Server {
	t.Helper()
	targets, err := publishedPorts(writeRuntimeConfig(t, fmt.Sprintf("containers:\n  - name: echo\n    ports: ['%d:9']\n    tunnel-ports: [%d]\n", port, port)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !enabled {
		targets = nil
	}
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}
	shim := NewShimServer(tinfoilattestation.Identity{}, 0, id, nil, nil,
		&config.ExternalConfig{}, "127.0.0.1:9999", targets)

	server := httptest.NewUnstartedServer(shim)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func connectTo(t *testing.T, server *httptest.Server, authority string, header http.Header) (*http.Response, io.WriteCloser) {
	t.Helper()
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: tunnelTestDomain},
		DialTLSContext: func(_ context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial(network, server.Listener.Addr().String(), cfg)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	body, writer := io.Pipe()
	resp, err := transport.RoundTrip(&http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Scheme: "https", Host: authority},
		Host:       authority,
		Header:     header,
		Body:       body,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
	})
	if err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, writer
}

func echoThrough(t *testing.T, resp *http.Response, writer io.WriteCloser) {
	t.Helper()
	if _, err := writer.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(echoed) != "ping" {
		t.Fatalf("echoed %q", echoed)
	}
	writer.Close()
}

func TestTunnelReachesPublishedPortOnly(t *testing.T) {
	port := echoListener(t)
	server := tunnelServer(t, port, true)

	for _, host := range []string{tunnelTestDomain, "attacker.example.com"} {
		resp, writer := connectTo(t, server, fmt.Sprintf("%s:%d", host, port), http.Header{})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT %s status = %d", host, resp.StatusCode)
		}
		echoThrough(t, resp, writer)
	}

	resp, _ := connectTo(t, server, fmt.Sprintf("%s:%d", tunnelTestDomain, port+1), http.Header{})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("undeclared port status = %d, want 404", resp.StatusCode)
	}
}

func TestTunnelRequiresWorkloadOptIn(t *testing.T) {
	port := echoListener(t)
	server := tunnelServer(t, port, false)
	for _, authorization := range []string{"", "Bearer old-shim-key"} {
		resp, writer := connectTo(t, server, fmt.Sprintf("%s:%d", tunnelTestDomain, port), http.Header{"Authorization": []string{authorization}})
		writer.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("non-opted-in port status = %d", resp.StatusCode)
		}
	}
}

func TestTunnelOnlyHandlesHTTP2Connect(t *testing.T) {
	shim := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "shim") })

	recorder := httptest.NewRecorder()
	tunnels(nil, shim).ServeHTTP(recorder, httptest.NewRequest(http.MethodConnect, "https://"+tunnelTestDomain+":2300", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HTTP/1 CONNECT status = %d, want 405", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	tunnels(nil, shim).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if recorder.Body.String() != "shim" {
		t.Fatalf("body = %q, want the shim handler's", recorder.Body)
	}
}
