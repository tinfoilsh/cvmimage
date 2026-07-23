//go:build tinfoil_debug_image && linux && amd64

package main

import (
	"reflect"
	"testing"
)

func TestDebugConsoleCommandIsFixedSelfExec(t *testing.T) {
	command := debugConsoleCommand()
	if command.Name != "tinfoil-debug-console" || command.Path != selfExecPath ||
		!reflect.DeepEqual(command.Args, []string{debugConsoleArg}) || command.Dir != "/" {
		t.Fatalf("debug console command = %+v", command)
	}
}

func TestDispatchDebugConsoleRejectsNonExactInvocation(t *testing.T) {
	for _, args := range [][]string{
		{"tinfoil-init"},
		{"tinfoil-init", "--unknown"},
		{"tinfoil-init", debugConsoleArg, "extra"},
	} {
		handled, err := dispatchDebugConsole(args)
		if handled || err != nil {
			t.Fatalf("dispatchDebugConsole(%q) = %v, %v; want false, nil", args, handled, err)
		}
	}
}
