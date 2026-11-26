package kernelcmdline

import (
	"fmt"
	"os"
	"strings"
)

const path = "/proc/cmdline"
const nonCCFlag = "tinfoil-non-cc=on"

type Values struct {
	NonCC bool
}

func Read() (Values, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Values{}, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(string(data)), nil
}

func Parse(cmdline string) Values {
	var values Values
	for _, field := range strings.Fields(cmdline) {
		if field == nonCCFlag {
			values.NonCC = true
		}
	}
	return values
}
