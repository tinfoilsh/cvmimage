//go:build tinfoil_debug_image && linux && amd64

package supervisor

import (
	"os"
	"testing"
)

func TestNewConsoleProcessCachesIdentity(t *testing.T) {
	const (
		pid  = 1234
		name = "debug-console"
	)
	process := newConsoleProcess(&os.Process{Pid: pid}, name)
	if process.PID() != pid || process.name != name {
		t.Fatalf("process identity = (%d, %q), want (%d, %q)", process.PID(), process.name, pid, name)
	}
	child, ok := process.child.(osChild)
	if !ok || child.processID != pid {
		t.Fatalf("child process ID = %d, %v; want %d, true", child.processID, ok, pid)
	}
}
