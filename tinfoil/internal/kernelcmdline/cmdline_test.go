package kernelcmdline

import "testing"

func TestParse(t *testing.T) {
	for _, test := range []struct {
		name      string
		cmdline   string
		wantDebug bool
	}{
		{name: "production", cmdline: "console=hvc0 root=/dev/mapper/root"},
		{name: "debug", cmdline: "console=hvc0 tinfoil-debug=on", wantDebug: true},
		{name: "other debug forms", cmdline: "tinfoil-debug tinfoil-debug=off other=tinfoil-debug=on"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Parse(test.cmdline)
			if got.Debug != test.wantDebug {
				t.Fatalf("Parse() = %#v, want debug %t", got, test.wantDebug)
			}
		})
	}
}
