package config

import (
	"fmt"

	"tinfoil/internal/device"
	"tinfoil/internal/guestnet"
)

// LoadExternal reads the host inputs required to boot the guest.
func LoadExternal(path string) (*ExternalConfig, []byte, error) {
	data, err := device.ReadDiskPayload(path, 1<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("reading external config: %w", err)
	}
	value, err := decodeBootExternal(data)
	return value, data, err
}

func decodeBootExternal(data []byte) (*ExternalConfig, error) {
	value, err := DecodeExternal(data)
	if err != nil {
		return nil, fmt.Errorf("parsing external config: %w", err)
	}
	if err := guestnet.Validate(value.Network); err != nil {
		return nil, fmt.Errorf("external network config: %w", err)
	}
	return value, nil
}
