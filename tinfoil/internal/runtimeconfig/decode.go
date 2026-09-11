package runtimeconfig

import runtimeconfig "github.com/tinfoilsh/tinfoil-config"

// Decode applies the guest's measured debug mode while validating the wire schema.
func Decode(data []byte, debug bool) (*runtimeconfig.Config, error) {
	var options runtimeconfig.Options
	if debug {
		options.Mode = runtimeconfig.HostDebugMode
	}
	return runtimeconfig.Decode(data, options)
}
