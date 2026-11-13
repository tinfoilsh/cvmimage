package runtime

import (
	"os"
	"strings"
	"testing"
)

// The fixture is the unedited flags output of two processors of an AMD EPYC.
func realCPUInfo(t *testing.T) string {
	t.Helper()
	info, err := os.ReadFile("testdata/cpuinfo")
	if err != nil {
		t.Fatal(err)
	}
	return string(info)
}

// withoutFlag removes one whole flag from the given processor's flags line.
func withoutFlag(t *testing.T, info string, processor int, flag string) string {
	t.Helper()
	lines := strings.Split(info, "\n")
	seen := -1
	for index, line := range lines {
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != cpuFlagsName {
			continue
		}
		if seen++; seen != processor {
			continue
		}
		var kept []string
		for _, reported := range strings.Fields(value) {
			if reported != flag {
				kept = append(kept, reported)
			}
		}
		if len(kept) == len(strings.Fields(value)) {
			t.Fatalf("fixture processor %d does not report %s", processor, flag)
		}
		lines[index] = name + ": " + strings.Join(kept, " ")
		return strings.Join(lines, "\n")
	}
	t.Fatalf("fixture has no processor %d", processor)
	return ""
}

func TestRequiredCPUFlagsAcceptARealProcessor(t *testing.T) {
	if err := checkCPUFlags(realCPUInfo(t), requiredCPUFlags); err != nil {
		t.Fatal(err)
	}
}

func TestEveryRequiredCPUFlagMustBeReportedByEveryProcessor(t *testing.T) {
	info := realCPUInfo(t)
	for _, flag := range requiredCPUFlags {
		for processor := range 2 {
			err := checkCPUFlags(withoutFlag(t, info, processor, flag), requiredCPUFlags)
			if err == nil || !strings.Contains(err.Error(), flag) {
				t.Fatalf("processor %d without %s: %v", processor, flag, err)
			}
		}
	}
}

func TestCPUFlagsMatchWholeNames(t *testing.T) {
	// The fixture reports vaes and vpclmulqdq, which contain required names.
	info := withoutFlag(t, withoutFlag(t, realCPUInfo(t), 0, "aes"), 0, "pclmulqdq")
	for _, lookalike := range []string{"vaes", "vpclmulqdq"} {
		if !strings.Contains(info, " "+lookalike) {
			t.Fatalf("fixture does not report %s", lookalike)
		}
	}
	err := checkCPUFlags(info, requiredCPUFlags)
	if err == nil || !strings.Contains(err.Error(), "aes pclmulqdq") {
		t.Fatalf("lookalike flags satisfied the check: %v", err)
	}
}

func TestCPUFlagsMustBeReported(t *testing.T) {
	for name, info := range map[string]string{
		"empty":         "",
		"no flags line": "processor\t: 0\nmodel name\t: unknown\n",
	} {
		if err := checkCPUFlags(info, requiredCPUFlags); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
