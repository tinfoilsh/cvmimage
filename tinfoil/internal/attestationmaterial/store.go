package attestationmaterial

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func WriteJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", filepath.Base(path), err)
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("creating temporary %s: %w", path, err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("setting permissions on %s: %w", tempName, err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("writing %s: %w", tempName, err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("syncing %s: %w", tempName, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tempName, err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}
