package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func withDebugShellTestCmdline(t *testing.T, contents string) {
	t.Helper()
	old := procCmdlinePath
	path := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	procCmdlinePath = path
	t.Cleanup(func() { procCmdlinePath = old })
}

func TestDebugFailureShellEnabledRequiresExactDebugFlag(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmdline  string
		wantBool bool
	}{
		{name: "absent", cmdline: "console=hvc0 root=/dev/mapper/root\n"},
		{name: "off", cmdline: "console=hvc0 tinfoil-debug=off\n"},
		{name: "substring", cmdline: "console=hvc0 foo=tinfoil-debug=on\n"},
		{name: "enabled", cmdline: "console=hvc0 tinfoil-debug=on root=/dev/mapper/root\n", wantBool: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDebugShellTestCmdline(t, tc.cmdline)
			if got := debugFailureShellEnabled(); got != tc.wantBool {
				t.Fatalf("debugFailureShellEnabled() = %t, want %t", got, tc.wantBool)
			}
		})
	}
}

func TestMaybeDropToDebugFailureShellSkipsWithoutDebugFlag(t *testing.T) {
	withDebugShellTestCmdline(t, "console=hvc0 tinfoil-debug=off\n")
	old := runDebugFailureShell
	t.Cleanup(func() { runDebugFailureShell = old })
	runDebugFailureShell = func() error {
		t.Fatal("debug failure shell should not run without tinfoil-debug=on")
		return nil
	}

	maybeDropToDebugFailureShell(errors.New("boot failed"))
}

func TestMaybeDropToDebugFailureShellRunsWithDebugFlag(t *testing.T) {
	withDebugShellTestCmdline(t, "console=hvc0 tinfoil-debug=on\n")
	old := runDebugFailureShell
	t.Cleanup(func() { runDebugFailureShell = old })
	called := false
	runDebugFailureShell = func() error {
		called = true
		return nil
	}

	maybeDropToDebugFailureShell(errors.New("boot failed"))
	if !called {
		t.Fatal("debug failure shell was not launched")
	}
}
