package runtime

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

const (
	cpuInfoPath      = "/proc/cpuinfo"
	cpuFlagsName     = "flags"
	cpuProcessorName = "processor"
)

// The host chooses which CPU features the guest sees, and that choice is not
// measured. The kernel turns these protections on only when they are reported,
// and both the kernel and Go fall back to table-based AES without the
// instructions, so the guest refuses to run without them.
var requiredCPUFlags = []string{
	"nx", "smep", "smap",
	"aes", "pclmulqdq", "ssse3", "sse4_1",
}

// RequireCPUFeatures fails unless every processor reports the required flags.
func RequireCPUFeatures(log LogFunc) error {
	info, err := os.ReadFile(cpuInfoPath)
	if err != nil {
		return err
	}
	if err := checkCPUFlags(string(info), requiredCPUFlags); err != nil {
		return err
	}
	logf(log, "required CPU features present: %s", strings.Join(requiredCPUFlags, " "))
	return nil
}

func checkCPUFlags(info string, required []string) error {
	processors := 0
	// The kernel numbers processors in their "processor" field; the count of
	// flags lines differs from it when a processor is offline.
	processor := ""
	for line := range strings.SplitSeq(info, "\n") {
		name, value, found := strings.Cut(line, ":")
		key := strings.TrimSpace(name)
		if found && key == cpuProcessorName {
			processor = strings.TrimSpace(value)
			continue
		}
		if !found || key != cpuFlagsName {
			continue
		}
		if processor == "" {
			processor = fmt.Sprint(processors)
		}
		processors++
		reported := strings.Fields(value)
		var missing []string
		for _, flag := range required {
			if !slices.Contains(reported, flag) {
				missing = append(missing, flag)
			}
		}
		if len(missing) != 0 {
			return fmt.Errorf("processor %s does not report required CPU features: %s",
				processor, strings.Join(missing, " "))
		}
		processor = ""
	}
	if processors == 0 {
		return errors.New("no processor reports its CPU features")
	}
	return nil
}
