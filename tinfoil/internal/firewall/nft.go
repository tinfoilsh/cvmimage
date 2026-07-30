package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

func Apply(script string) error {
	output, err := ApplyOutput(script)
	if err != nil {
		return fmt.Errorf("nft -f -: %w (%s)\nscript:\n%s", err, output, script)
	}
	return nil
}

func ApplyOutput(script string) ([]byte, error) {
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(script)
	return command.CombinedOutput()
}
