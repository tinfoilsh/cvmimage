package secrets

import (
	"slices"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"
)

// References selects the declared secrets passed to the container manager.
func References(config *runtimeconfig.Config) []string {
	var names []string
	for _, container := range config.Containers {
		names = append(names, container.Secrets...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}
