package kernelcmdline

import (
	"fmt"
	"os"
	"strings"
)

const path = "/proc/cmdline"

func DebugEnabled() (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}
	return HasDebug(string(data)), nil
}

func HasDebug(cmdline string) bool {
	for _, field := range strings.Fields(cmdline) {
		if field == "tinfoil-debug=on" {
			return true
		}
	}
	return false
}
