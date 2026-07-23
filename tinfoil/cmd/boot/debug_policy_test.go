package main

import (
	"strings"
	"testing"
)

func TestParseKernelCmdline(t *testing.T) {
	tests := []struct {
		name       string
		cmdline    string
		wantHash   string
		wantDebug  bool
		wantErrSub string
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
			name:       "reject duplicate debug flag",
			cmdline:    "tinfoil-debug=on tinfoil-debug=on",
			wantErrSub: "duplicate kernel command-line parameter tinfoil-debug",
		},
		{
			name:       "reject bare debug flag",
			cmdline:    "quiet tinfoil-debug root=/dev/vda",
			wantErrSub: "malformed kernel command-line parameter tinfoil-debug",
		},
		{
			name:       "reject other debug value",
			cmdline:    "tinfoil-debug=off",
			wantErrSub: `invalid kernel command-line parameter tinfoil-debug="off"`,
		},
		{
			name:       "reject empty debug value",
			cmdline:    "tinfoil-debug=",
			wantErrSub: `invalid kernel command-line parameter tinfoil-debug=""`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseKernelCmdline(test.cmdline)
			if test.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("parseKernelCmdline error = %v, want %q", err, test.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKernelCmdline: %v", err)
			}
			if got.ConfigHash != test.wantHash {
				t.Fatalf("ConfigHash = %q, want %q", got.ConfigHash, test.wantHash)
			}
			if got.Debug != test.wantDebug {
				t.Fatalf("Debug = %t, want %t", got.Debug, test.wantDebug)
			}
		})
	}
}
