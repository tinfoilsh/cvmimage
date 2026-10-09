package kernelcmdline

import "testing"

func TestParse(t *testing.T) {
	for _, test := range []struct {
		name      string
		cmdline   string
		wantDebug bool
		wantNonCC bool
	}{
		{name: "production", cmdline: "console=hvc0 root=/dev/mapper/root"},
		{name: "debug", cmdline: "console=hvc0 tinfoil-debug=on", wantDebug: true},
		{name: "other debug forms", cmdline: "tinfoil-debug tinfoil-debug=off other=tinfoil-debug=on"},
		{name: "non-CC", cmdline: "tinfoil-non-cc=on", wantNonCC: true},
		{name: "non-CC debug", cmdline: "tinfoil-debug=on tinfoil-non-cc=on", wantDebug: true, wantNonCC: true},
		{name: "other non-CC forms", cmdline: "tinfoil-non-cc tinfoil-non-cc=off other=tinfoil-non-cc=on"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Parse(test.cmdline)
			if got.Debug != test.wantDebug {
				t.Fatalf("Parse() = %#v, want debug %t", got, test.wantDebug)
			}
			if got.NonCC != test.wantNonCC {
				t.Fatalf("Parse() = %#v, want non-CC %t", got, test.wantNonCC)
			}
		})
	}
}
