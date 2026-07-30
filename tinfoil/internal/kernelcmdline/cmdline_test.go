package kernelcmdline

import "testing"

func TestHasDebug(t *testing.T) {
	for _, test := range []struct {
		name    string
		cmdline string
		want    bool
	}{
		{name: "enabled", cmdline: "console=hvc0 tinfoil-debug=on", want: true},
		{name: "disabled", cmdline: "console=hvc0 tinfoil-debug=off"},
		{name: "missing", cmdline: "console=hvc0"},
		{name: "not substring", cmdline: "other=tinfoil-debug=on"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := HasDebug(test.cmdline); got != test.want {
				t.Fatalf("HasDebug() = %t, want %t", got, test.want)
			}
		})
	}
}
