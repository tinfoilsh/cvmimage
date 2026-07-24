package main

import "testing"

func TestParseKernelCmdline(t *testing.T) {
	tests := []struct {
		name      string
		cmdline   string
		wantHash  string
		wantDebug bool
	}{
		{
			name:      "production by default",
			cmdline:   "console=ttyS0 tinfoil-config-hash=abc root=/dev/vda",
			wantHash:  "abc",
			wantDebug: false,
		},
		{
			name:      "debug on exact token",
			cmdline:   "tinfoil-config-hash=abc tinfoil-debug=on quiet",
			wantHash:  "abc",
			wantDebug: true,
		},
		{
			name:      "duplicate exact token remains debug",
			cmdline:   "tinfoil-debug=on tinfoil-debug=on",
			wantDebug: true,
		},
		{
			name:      "other forms remain production",
			cmdline:   "tinfoil-debug tinfoil-debug=off tinfoil-debug=",
			wantDebug: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseKernelCmdline(test.cmdline)
			if got.ConfigHash != test.wantHash {
				t.Fatalf("ConfigHash = %q, want %q", got.ConfigHash, test.wantHash)
			}
			if got.Debug != test.wantDebug {
				t.Fatalf("Debug = %t, want %t", got.Debug, test.wantDebug)
			}
		})
	}
}
