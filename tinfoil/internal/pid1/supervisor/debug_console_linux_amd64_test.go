//go:build tinfoil_debug_image && linux && amd64

package supervisor

import (
	"os"
	"testing"
)

func TestStartConsoleUsesManagedEphemeralScope(t *testing.T) {
	sigchld := make(chan os.Signal, 1)
	backend := newFakeBackend(sigchld)
	manager := newManager(backend, sigchld, nil)
	console, err := os.CreateTemp(t.TempDir(), "console")
	if err != nil {
		t.Fatal(err)
	}
	defer console.Close()

	process, err := manager.StartConsole(Command{Name: "debug-console", Path: "/bin/sh"}, console)
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	child := backend.children[process.PID()]
	backend.mu.Unlock()
	if child.scope != "" {
		t.Fatalf("console scope = %q, want ephemeral scope", child.scope)
	}
	if !child.options.console || len(child.options.files) != 3 {
		t.Fatalf("console options = %#v", child.options)
	}
	for index, file := range child.options.files {
		if file != console {
			t.Fatalf("console file %d = %p, want %p", index, file, console)
		}
	}
}
