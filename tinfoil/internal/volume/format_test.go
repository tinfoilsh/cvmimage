package volume

import "testing"

func TestRunFormatterRejectsUnusableInvocations(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing owner", []string{"worker", FormatMode, "/dev/mapper/tinfoil-volume-workspace"}},
		{"owner beyond range", []string{"worker", FormatMode, "/dev/mapper/tinfoil-volume-workspace", "65535"}},
		{"owner not a number", []string{"worker", FormatMode, "/dev/mapper/tinfoil-volume-workspace", "sandbox"}},
		{"device outside mapper", []string{"worker", FormatMode, "/dev/sda1", "0"}},
		{"device without the mapping prefix", []string{"worker", FormatMode, "/dev/mapper/workspace", "0"}},
		{"device name not a volume", []string{"worker", FormatMode, "/dev/mapper/tinfoil-volume-Workspace", "0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := RunFormatter(test.args); err == nil {
				t.Fatalf("RunFormatter(%v) accepted the invocation", test.args)
			}
		})
	}
}
