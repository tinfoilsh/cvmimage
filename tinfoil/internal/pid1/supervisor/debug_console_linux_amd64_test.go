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
	cgroup := &processCgroup{path: "/sys/fs/cgroup/test"}
	process := newConsoleProcess(&os.Process{Pid: pid}, name, cgroup)
	if process.PID() != pid || process.name != name {
		t.Fatalf("process identity = (%d, %q), want (%d, %q)", process.PID(), process.name, pid, name)
	}
	child, ok := process.child.(*osChild)
	if !ok {
		t.Fatalf("child process type = %T, want *osChild", process.child)
	}
	if child.processID != pid || child.cgroup != cgroup {
		t.Fatalf("child identity = (%d, %p), want (%d, %p)", child.processID, child.cgroup, pid, cgroup)
	}
}
