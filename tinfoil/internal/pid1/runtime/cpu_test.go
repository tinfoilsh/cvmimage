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

func TestCPUFlagsErrorNamesTheKernelProcessor(t *testing.T) {
	// Processor 1 is offline, so the second processor listed is processor 2.
	info := strings.Replace(withoutFlag(t, realCPUInfo(t), 1, "smep"), "processor\t: 1", "processor\t: 2", 1)
	err := checkCPUFlags(info, requiredCPUFlags)
	if err == nil || !strings.HasPrefix(err.Error(), "processor 2 ") {
		t.Fatalf("error = %v, want it to name processor 2", err)
	}
}

func TestCPUFlagsMustBeReported(t *testing.T) {
	all := strings.Join(requiredCPUFlags, " ")
	for name, info := range map[string]string{
		"empty":                 "",
		"only lookalike fields": "processor\t: 0\nvmx flags\t: " + all + "\nbugs\t\t: " + all + "\n",
		"no flags line":         "processor\t: 0\nmodel name\t: unknown\n",
	} {
		if err := checkCPUFlags(info, requiredCPUFlags); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
