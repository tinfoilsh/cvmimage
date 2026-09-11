package runtimeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	config "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/device"
)

var hexHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// LoadVerified reads and validates a measured config without publishing it.
func LoadVerified(path, expectedHash string, debug bool) (*config.Config, []byte, error) {
	data, err := device.ReadDiskPayload(path, 1<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("reading config disk: %w", err)
	}
	if expectedHash == "" {
		return nil, nil, fmt.Errorf("getting expected config hash: parameter tinfoil-config-hash not found in cmdline")
	}
	if !hexHashPattern.MatchString(expectedHash) {
		return nil, nil, fmt.Errorf("invalid config hash format in cmdline: %s", expectedHash)
	}
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])
	if expectedHash != actual {
		return nil, nil, fmt.Errorf("config hash mismatch: expected %s, got %s", expectedHash, actual)
	}
	value, err := Decode(data, debug)
	if err != nil {
		return nil, nil, err
	}
	if err := validateModelCount(len(value.Models)); err != nil {
		return nil, nil, err
	}
	return value, data, nil
}

func validateModelCount(count int) error {
	if count < 0 || count > device.MaxModelDisks {
		return fmt.Errorf("models must contain at most %d entries (got %d)", device.MaxModelDisks, count)
	}
	return nil
}
