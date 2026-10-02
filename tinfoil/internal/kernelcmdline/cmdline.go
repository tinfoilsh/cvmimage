package kernelcmdline

import (
	"fmt"
	"os"
	"strings"
)

const path = "/proc/cmdline"

type Values struct {
	Debug bool
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
		if field == "tinfoil-debug=on" {
			values.Debug = true
		}
	}
	return values
}
