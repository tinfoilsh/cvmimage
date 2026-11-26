package kernelcmdline

import "testing"

func TestParse(t *testing.T) {
	for _, test := range []struct {
		name      string
		cmdline   string
		wantNonCC bool
	}{
		{name: "production", cmdline: "console=hvc0 root=/dev/mapper/root"},
		{name: "non-CC", cmdline: "tinfoil-non-cc=on", wantNonCC: true},
		{name: "other non-CC forms", cmdline: "tinfoil-non-cc tinfoil-non-cc=off other=tinfoil-non-cc=on"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Parse(test.cmdline)
			if got.NonCC != test.wantNonCC {
				t.Fatalf("Parse() = %#v, want non-CC %t", got, test.wantNonCC)
			}
		})
	}
}
