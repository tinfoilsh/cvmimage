package main

import (
	"reflect"
	"testing"
)

func TestParseInvocationRejectsUnusableRequests(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing name", []string{"worker", "--models=1", "--index=0"}},
		{"uppercase name", []string{"worker", "--name=Workspace"}},
		{"negative index", []string{"worker", "--name=workspace", "--index=-1"}},
		{"negative owner", []string{"worker", "--name=workspace", "--owner=-1"}},
		{"owner beyond range", []string{"worker", "--name=workspace", "--owner=65535"}},
		{"more disks than slots", []string{"worker", "--name=workspace", "--models=24", "--index=0"}},
		{"trailing arguments", []string{"worker", "--name=workspace", "extra"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseInvocation(test.args); err == nil {
				t.Fatalf("parseInvocation(%v) accepted the request", test.args)
			}
		})
	}
}

func TestParseInvocationAcceptsDeclaredVolume(t *testing.T) {
	parsed, err := parseInvocation([]string{"worker", "--models=2", "--index=1", "--name=workspace", "--exec=true", "--owner=1000"})
	if err != nil {
		t.Fatal(err)
	}
	want := invocation{models: 2, index: 1, name: "workspace", executable: true, owner: 1000}
	if !reflect.DeepEqual(parsed, want) {
		t.Fatalf("parsed = %+v, want %+v", parsed, want)
	}
}

func TestParseInvocationOverlays(t *testing.T) {
	base := []string{"worker", "--name=workspace", "--exec=true", "--owner=1000"}
	for _, bad := range []string{
		"nix:nix/store:st:ore",            // target splits a fourth field
		"nix:nix/store:Store",             // target is not a single lowercase name
		"nix:nix/store:store/x",           // target holds a separator
		"nix:../etc:store",                // source escapes the pack
		"nix:nix/store,upperdir=/x:store", // option injection in source
		"n/x:nix/store:store",             // model holds a separator
	} {
		if _, err := parseInvocation(append(base, "--overlay="+bad)); err == nil {
			t.Fatalf("parseInvocation accepted overlay %q", bad)
		}
	}
	parsed, err := parseInvocation(append(base, "--overlay=nix:nix/store:store"))
	if err != nil {
		t.Fatal(err)
	}
	want := []overlay{{model: "nix", source: "nix/store", target: "store"}}
	if !reflect.DeepEqual(parsed.overlays, want) {
		t.Fatalf("overlays = %+v, want %+v", parsed.overlays, want)
	}
}

func TestRunFormatterRejectsUnusableInvocations(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing owner", []string{"worker", formatMode, "/dev/mapper/tinfoil-volume-workspace"}},
		{"owner beyond range", []string{"worker", formatMode, "/dev/mapper/tinfoil-volume-workspace", "65535"}},
		{"owner not a number", []string{"worker", formatMode, "/dev/mapper/tinfoil-volume-workspace", "sandbox"}},
		{"device outside mapper", []string{"worker", formatMode, "/dev/sda1", "0"}},
		{"device without the mapping prefix", []string{"worker", formatMode, "/dev/mapper/workspace", "0"}},
		{"device name not a volume", []string{"worker", formatMode, "/dev/mapper/tinfoil-volume-Workspace", "0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runFormatter(test.args); err == nil {
				t.Fatalf("runFormatter(%v) accepted the invocation", test.args)
			}
		})
	}
}
