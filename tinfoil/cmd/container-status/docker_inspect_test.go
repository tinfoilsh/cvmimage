package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func serveDockerSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listening on Unix socket: %v", err)
	}
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serving Unix socket: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("closing test server: %v", err)
		}
		<-done
	})
	return socketPath
}

func TestDockerInspectClientFixedRequestAndResponse(t *testing.T) {
	const containerName = "model.worker"
	var requests atomic.Int32
	socketPath := serveDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.Host != "docker" {
			t.Errorf("host = %q, want docker", r.Host)
		}
		if r.URL.RequestURI() != "/v1.44/containers/model.worker/json" {
			t.Errorf("request URI = %q", r.URL.RequestURI())
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, `{
  "Id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "Name":"/model.worker",
  "RestartCount":2,
  "State":{
    "Status":"running",
    "OOMKilled":false,
    "ExitCode":0,
    "Error":"",
    "StartedAt":"2026-07-24T01:02:03Z",
    "FinishedAt":"0001-01-01T00:00:00Z",
    "Health":{"Status":"healthy","FailingStreak":0,"Log":[{"Start":"2026-07-24T01:02:04Z","End":"2026-07-24T01:02:05Z","ExitCode":0,"Output":"ignored"}]}
  },
  "HostConfig":{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":4},"Privileged":true},
  "Config":{"Image":"example/model@sha256:abc","Env":["IGNORED=1"]},
  "Mounts":[{"Source":"ignored"}]
}`)
	}))
	client := newDockerInspectClient(socketPath)
	t.Cleanup(client.CloseIdleConnections)

	inspect, err := client.ContainerInspect(context.Background(), containerName)
	if err != nil {
		t.Fatalf("ContainerInspect returned error: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("request count = %d, want 1", requests.Load())
	}
	if inspect.Base == nil || inspect.Base.ID != strings.Repeat("a", 64) || inspect.Base.Name != "/model.worker" {
		t.Fatalf("base inspect = %#v", inspect.Base)
	}
	if inspect.Base.RestartCount != 2 || inspect.Base.State == nil || inspect.Base.State.Status != "running" {
		t.Fatalf("state inspect = %#v", inspect.Base)
	}
	if inspect.Base.HostConfig == nil || inspect.Base.HostConfig.RestartPolicy.Name != "on-failure" || inspect.Base.HostConfig.RestartPolicy.MaximumRetryCount != 4 {
		t.Fatalf("host config = %#v", inspect.Base.HostConfig)
	}
	if inspect.Config == nil || inspect.Config.Image != "example/model@sha256:abc" {
		t.Fatalf("config = %#v", inspect.Config)
	}
	if health := inspect.Base.State.Health; health == nil || len(health.Log) != 1 || health.Log[0].ExitCode != 0 {
		t.Fatalf("health = %#v", health)
	}
}

func TestDockerInspectClientEscapesContainerName(t *testing.T) {
	socketPath := serveDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/v1.44/containers/name%2Fwith%20space/json" {
			t.Errorf("request URI = %q", r.RequestURI)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Id":%q,"State":{"Status":"running","ExitCode":0}}`, strings.Repeat("b", 64))
	}))
	client := newDockerInspectClient(socketPath)
	t.Cleanup(client.CloseIdleConnections)
	if _, err := client.ContainerInspect(context.Background(), "name/with space"); err != nil {
		t.Fatalf("ContainerInspect returned error: %v", err)
	}
}

func TestDockerInspectClientBoundsContainerReference(t *testing.T) {
	client := newDockerInspectClient(filepath.Join(t.TempDir(), "unused.sock"))
	t.Cleanup(client.CloseIdleConnections)
	for _, name := range []string{"", strings.Repeat("a", maxContainerReferenceSize+1)} {
		if _, err := client.ContainerInspect(context.Background(), name); err == nil || !strings.Contains(err.Error(), "invalid container reference length") {
			t.Fatalf("reference length %d error = %v", len(name), err)
		}
	}
}

func TestDockerInspectClientRejectsUnexpectedResponses(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        string
	}{
		{name: "error status", status: http.StatusInternalServerError, contentType: "application/json", body: `{"message":"sensitive"}`, want: "HTTP status 500"},
		{name: "redirect", status: http.StatusTemporaryRedirect, contentType: "application/json", body: `{}`, want: "HTTP status 307"},
		{name: "text content type", status: http.StatusOK, contentType: "text/plain", body: `{}`, want: "non-JSON content type"},
		{name: "malformed JSON", status: http.StatusOK, contentType: "application/json", body: `{`, want: "decoding inspect response"},
		{name: "trailing JSON", status: http.StatusOK, contentType: "application/json", body: `{} {}`, want: "decoding inspect response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath := serveDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.name == "redirect" {
					w.Header().Set("Location", "http://ignored/version")
				}
				if test.contentType != "" {
					w.Header().Set("Content-Type", test.contentType)
				}
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			client := newDockerInspectClient(socketPath)
			t.Cleanup(client.CloseIdleConnections)
			_, err := client.ContainerInspect(context.Background(), "model")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("error exposed daemon response body: %v", err)
			}
		})
	}
}

func TestDockerInspectClientRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "missing container ID", body: `{"State":{"Status":"running","ExitCode":0}}`, want: "invalid container ID"},
		{name: "short container ID", body: `{"Id":"abc","State":{"Status":"running","ExitCode":0}}`, want: "invalid container ID"},
		{name: "negative restart count", body: fmt.Sprintf(`{"Id":%q,"RestartCount":-1,"State":{"Status":"running","ExitCode":0}}`, strings.Repeat("a", 64)), want: "negative restart count"},
		{name: "missing state", body: fmt.Sprintf(`{"Id":%q}`, strings.Repeat("a", 64)), want: "missing state"},
		{name: "missing state status", body: fmt.Sprintf(`{"Id":%q,"State":{"ExitCode":0}}`, strings.Repeat("a", 64)), want: "invalid state status"},
		{name: "unknown state status", body: fmt.Sprintf(`{"Id":%q,"State":{"Status":"unknown","ExitCode":0}}`, strings.Repeat("a", 64)), want: "invalid state status"},
		{name: "invalid exit code", body: fmt.Sprintf(`{"Id":%q,"State":{"Status":"exited","ExitCode":256}}`, strings.Repeat("a", 64)), want: "invalid exit code"},
		{name: "invalid started time", body: fmt.Sprintf(`{"Id":%q,"State":{"Status":"running","ExitCode":0,"StartedAt":"invalid"}}`, strings.Repeat("a", 64)), want: "invalid started_at"},
		{name: "invalid finished time", body: fmt.Sprintf(`{"Id":%q,"State":{"Status":"exited","ExitCode":0,"FinishedAt":"invalid"}}`, strings.Repeat("a", 64)), want: "invalid finished_at"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath := serveDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, test.body)
			}))
			client := newDockerInspectClient(socketPath)
			t.Cleanup(client.CloseIdleConnections)
			_, err := client.ContainerInspect(context.Background(), "model")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestDockerInspectClientDistinguishesNotFound(t *testing.T) {
	socketPath := serveDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not JSON")
	}))
	client := newDockerInspectClient(socketPath)
	t.Cleanup(client.CloseIdleConnections)
	_, err := client.ContainerInspect(context.Background(), "missing")
	if !errors.Is(err, errContainerNotFound) {
		t.Fatalf("error = %v, want errContainerNotFound", err)
	}
}

func TestDockerInspectClientBoundsResponse(t *testing.T) {
	tests := []struct {
		name          string
		contentLength string
		body          string
		want          string
	}{
		{name: "declared too large", contentLength: fmt.Sprint(maxInspectResponseSize + 1), body: `{}`, want: "invalid content length"},
		{name: "chunked too large", body: strings.Repeat(" ", maxInspectResponseSize+1), want: "exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath := serveDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if test.contentLength != "" {
					w.Header().Set("Content-Length", test.contentLength)
				}
				if test.name == "chunked too large" {
					w.Header().Set("Transfer-Encoding", "chunked")
					w.(http.Flusher).Flush()
				}
				fmt.Fprint(w, test.body)
			}))
			client := newDockerInspectClient(socketPath)
			t.Cleanup(client.CloseIdleConnections)
			_, err := client.ContainerInspect(context.Background(), "model")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestDockerInspectClientHonorsContext(t *testing.T) {
	socketPath := serveDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	client := newDockerInspectClient(socketPath)
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.ContainerInspect(ctx, "model")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
}

func TestDockerInspectClientFailsClosedWithoutSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "missing.sock")
	client := newDockerInspectClient(socketPath)
	t.Cleanup(client.CloseIdleConnections)
	_, err := client.ContainerInspect(context.Background(), "model")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want missing socket", err)
	}
}
