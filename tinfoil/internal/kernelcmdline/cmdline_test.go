package kernelcmdline

import "testing"

func TestParse(t *testing.T) {
	for _, test := range []struct {
		name      string
		cmdline   string
		wantHash  string
		wantDebug bool
	}{
		{name: "production", cmdline: "console=hvc0 tinfoil-config-hash=abc", wantHash: "abc"},
		{name: "debug", cmdline: "tinfoil-config-hash=abc tinfoil-debug=on", wantHash: "abc", wantDebug: true},
		{name: "first hash wins", cmdline: "tinfoil-config-hash=abc tinfoil-config-hash=ignored", wantHash: "abc"},
		{name: "other debug forms", cmdline: "tinfoil-debug tinfoil-debug=off other=tinfoil-debug=on"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Parse(test.cmdline)
			if got.ConfigHash != test.wantHash || got.Debug != test.wantDebug {
				t.Fatalf("Parse() = %#v, want hash %q debug %t", got, test.wantHash, test.wantDebug)
			}
		})
	}
}
