package volume

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"tinfoil/internal/devicemapper"
)

// VersionHKDF is temporary, explicit unlock support for pre-Argon2 volumes.
// Remove this file and the two VersionHKDF cases in volume.go after migration.
const VersionHKDF byte = 1

func validateLegacyKey(key []byte, initialize bool) error {
	if initialize {
		return errors.New("legacy HKDF volumes can only be unlocked; initialize with format 2")
	}
	if len(key) != 64 {
		return fmt.Errorf("legacy key is %d bytes, want 64", len(key))
	}
	return nil
}

func legacyTableKey(key []byte, initialize bool) ([]byte, int64, error) {
	if err := validateLegacyKey(key, initialize); err != nil {
		return nil, 0, err
	}
	tableKey, err := hkdf.Key(sha256.New, key, nil, "tinfoil volume table key v1", devicemapper.AuthenticatedKeyBytes)
	return tableKey, 0, err
}
