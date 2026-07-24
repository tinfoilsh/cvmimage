//go:build tinfoil_debug_image && linux && amd64

package main

import (
	"reflect"
	"testing"
)

func TestDebugConsoleCommandIsFixed(t *testing.T) {
	command := debugConsoleCommand()
	if command.Name != "tinfoil-debug-console" || command.Path != debugShellPath ||
		!reflect.DeepEqual(command.Args, []string{"ash", "-i"}) ||
		!reflect.DeepEqual(command.Env, []string{
			"HOME=/root",
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"TERM=linux",
		}) || command.Dir != "/" {
		t.Fatalf("debug console command = %+v", command)
	}
}
