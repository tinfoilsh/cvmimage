package hardening

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestShimInheritedUnixListener(t *testing.T) {
	const (
		childEnvironment = "TINFOIL_INHERITED_LISTENER_CHILD"
		listenerFD       = 3
		requestTimeout   = 10 * time.Second
		nonce            = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	if os.Getenv(childEnvironment) == "1" {
		runtime.LockOSThread()
		policy, _ := policyFor(ServiceShim)
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := (linuxServiceKernel{}).restrictSyscalls(
			policy.deniedSyscalls,
			policy.restrictNamespaceOps,
			policy.allowedSocketDomains,
		); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if fd >= 0 {
			unix.Close(fd)
		}
		if !errors.Is(err, unix.EAFNOSUPPORT) {
			t.Fatalf("creating a Unix socket returned %v, want EAFNOSUPPORT", err)
		}
		file := os.NewFile(listenerFD, "attestation-listener")
		listener, err := net.FileListener(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			io.WriteString(w, body)
			w.(http.Flusher).Flush()
			listener.Close()
		})}
		if err := server.Serve(listener); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		return
	}

	socketPath := filepath.Join(t.TempDir(), "attestation.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShimInheritedUnixListener$")
	command.Env = append(os.Environ(), childEnvironment+"=1")
	command.ExtraFiles = []*os.File{file}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			command.Process.Kill()
			command.Wait()
		}
		if t.Failed() {
			t.Logf("child output: %s", &output)
		}
	})
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: requestTimeout}
	response, err := client.Get("http://shim/?nonce=" + nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != nonce {
		t.Fatalf("inherited listener returned %d %q, want 200 %q", response.StatusCode, body, nonce)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("inherited-listener child failed: %v", err)
	}
}
