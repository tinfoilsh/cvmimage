package hardening

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tinfoil/internal/timequorum"
)

func TestShimInheritedTimeFeedPreservesSocketRestrictions(t *testing.T) {
	const childEnvironment = "TINFOIL_INHERITED_TIME_CHILD"
	const feedFD = 3
	const timeout = 10 * time.Second
	if os.Getenv(childEnvironment) == "1" {
		runtime.LockOSThread()
		policy, _ := policyFor(ServiceShim)
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := (linuxServiceKernel{}).restrictSyscalls(policy.deniedSyscalls, policy.restrictNamespaceOps, policy.allowedSocketDomains); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if fd >= 0 {
			unix.Close(fd)
		}
		if !errors.Is(err, unix.EAFNOSUPPORT) {
			t.Fatalf("Unix socket creation returned %v", err)
		}
		feed, err := timequorum.InheritChronyFeed(feedFD)
		if err != nil {
			t.Fatal(err)
		}
		defer feed.Close()
		now := time.Now()
		if err := feed.Send(context.Background(), timequorum.Agreement{UTC: now.UTC(), Observed: now, Operators: []timequorum.Operator{timequorum.Canonical, timequorum.Cloudflare, timequorum.Netnod}}); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "time.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	file, err := connection.File()
	connection.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShimInheritedTimeFeedPreservesSocketRestrictions$")
	command.Env = append(os.Environ(), childEnvironment+"=1")
	command.ExtraFiles = []*os.File{file}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("restricted time-feed child: %v\n%s", err, output)
	}
	if err := listener.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	const nativeSampleBytes = 40
	packet := make([]byte, nativeSampleBytes+1)
	n, _, err := listener.ReadFromUnix(packet)
	if err != nil || n != nativeSampleBytes {
		t.Fatalf("inherited feed wrote %d bytes, error=%v", n, err)
	}
}
