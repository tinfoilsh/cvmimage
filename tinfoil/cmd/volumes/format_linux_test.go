package main

import "testing"

func TestParseFormatter(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing owner", []string{"worker", "--format", "/dev/mapper/tinfoil-volume-workspace"}},
		{"owner beyond range", []string{"worker", "--format", "/dev/mapper/tinfoil-volume-workspace", "65535"}},
		{"owner not a number", []string{"worker", "--format", "/dev/mapper/tinfoil-volume-workspace", "sandbox"}},
		{"device outside mapper", []string{"worker", "--format", "/dev/sda1", "0"}},
		{"device without the mapping prefix", []string{"worker", "--format", "/dev/mapper/workspace", "0"}},
		{"device name not a volume", []string{"worker", "--format", "/dev/mapper/tinfoil-volume-Workspace", "0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseFormatter(test.args); err == nil {
				t.Fatalf("parseFormatter(%v) accepted the invocation", test.args)
			}
		})
	}
	got, err := parseFormatter([]string{"worker", "--format", "/dev/mapper/tinfoil-volume-workspace", "1000"})
	if err != nil || got.device != "/dev/mapper/tinfoil-volume-workspace" || got.owner != 1000 {
		t.Fatalf("valid formatter invocation: %+v, %v", got, err)
	}
}
