package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/timequorum"
)

const quorumExitChildEnv = "TINFOIL_TEST_QUORUM_EXIT_CHILD"
const quorumExitTestLimit = 5 * time.Second

type failedTimeMonitor struct{ fail <-chan struct{} }

func (monitor failedTimeMonitor) Run(ctx context.Context) error {
	select {
	case <-monitor.fail:
		return timequorum.ErrQuorumUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestQuorumLossClosesHijackedConnections(t *testing.T) {
	if os.Getenv(quorumExitChildEnv) == "1" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			connection, buffered, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: quorum-test\r\n\r\n")
			buffered.Flush()
			io.Copy(io.Discard, connection)
		})}
		go server.Serve(listener)
		fmt.Fprintln(os.Stdout, listener.Addr().String())
		fail := make(chan struct{})
		go func() { var trigger [1]byte; os.Stdin.Read(trigger[:]); close(fail) }()
		watchTimeQuorum(context.Background(), failedTimeMonitor{fail}, func() error { return nil })
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), quorumExitTestLimit)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQuorumLossClosesHijackedConnections$")
	command.Env = append(os.Environ(), quorumExitChildEnv+"=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	reader := bufio.NewReader(stdout)
	address, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("child startup: %v; %s", err, stderr.String())
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimSpace(address))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	connection.SetDeadline(deadline)
	if _, err := io.WriteString(connection, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: quorum-test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	stream := bufio.NewReader(connection)
	response, err := http.ReadResponse(stream, &http.Request{Method: http.MethodGet})
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("hijack response=%v error=%v", response, err)
	}
	if _, err := stdin.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.ReadByte(); err == nil {
		t.Fatal("hijacked stream remained open")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("quorum loss did not close hijacked stream")
		}
	}
	err = command.Wait()
	var exited *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exited) || exited.ExitCode() != 1 {
		t.Fatalf("child did not fail closed: %v; %s", err, stderr.String())
	}
}

func TestNormalShutdownDoesNotTriggerQuorumFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	watchTimeQuorum(ctx, failedTimeMonitor{make(chan struct{})}, func() error { t.Fatal("normal shutdown requested quorum termination"); return nil })
}

func TestUnhealthyAdmissionAndPrivateReadinessFailClosed(t *testing.T) {
	monitor := timequorum.NewMonitor(nil, nil, t.Logf)
	handler := timeAdmission(monitor, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, path := range []string{"/", "/.well-known/tinfoil-attestation", "/healthz"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s admitted without quorum", path)
		}
	}
	response := httptest.NewRecorder()
	newLocalControlHandler(http.NotFoundHandler(), timeReadyHandler(monitor)).ServeHTTP(response, httptest.NewRequest(http.MethodPost, boot.TimeReadyPath, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("private readiness returned HTTP %d", response.Code)
	}
}
