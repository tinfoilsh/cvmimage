package secretstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	"golang.org/x/sys/unix"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

const (
	handoffVersion  = 1
	maxHandoffBytes = 1 << 20
	requiredSeals   = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
)

type Store map[string]string

type handoff struct {
	Version      int               `json:"version"`
	ConfigDigest string            `json:"config_digest"`
	Secrets      map[string]string `json:"secrets"`
}

func NewHandoffFile() (*os.File, error) {
	fd, err := unix.MemfdCreate("tinfoil-container-secrets", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("creating secret handoff: %w", err)
	}
	return os.NewFile(uintptr(fd), "tinfoil-container-secrets"), nil
}

func ConfigDigest(source []byte) string {
	digest := sha256.Sum256(source)
	return hex.EncodeToString(digest[:])
}

func AllReferences(config *runtimeconfig.Config) []string {
	seen := map[string]struct{}{}
	for _, model := range config.Models {
		if model.KeySecret != "" {
			seen[model.KeySecret] = struct{}{}
		}
	}
	for _, name := range WorkloadReferences(config) {
		seen[name] = struct{}{}
	}
	return sortedKeys(seen)
}

func WorkloadReferences(config *runtimeconfig.Config) []string {
	seen := map[string]struct{}{}
	for _, container := range config.Containers {
		for _, name := range container.Secrets {
			seen[name] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func MissingReferences(config *runtimeconfig.Config, external *shimconfig.ExternalConfig) []string {
	var missing []string
	for _, name := range AllReferences(config) {
		if external.GetSecret(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

func WorkloadStore(config *runtimeconfig.Config, external *shimconfig.ExternalConfig) (Store, error) {
	store := make(Store)
	for _, name := range WorkloadReferences(config) {
		value := external.GetSecret(name)
		if value == "" {
			return nil, fmt.Errorf("declared container secret %q is unresolved", name)
		}
		store[name] = value
	}
	return store, nil
}

func WriteHandoff(file *os.File, configDigest string, store Store) error {
	if file == nil {
		return fmt.Errorf("secret handoff file is required")
	}
	for name, value := range store {
		if name == "" || value == "" || value == "null" {
			return fmt.Errorf("secret handoff contains unresolved secret %q", name)
		}
	}
	payload, err := json.Marshal(handoff{
		Version:      handoffVersion,
		ConfigDigest: configDigest,
		Secrets:      store,
	})
	if err != nil {
		return fmt.Errorf("encoding secret handoff: %w", err)
	}
	if len(payload) > maxHandoffBytes {
		return fmt.Errorf("secret handoff exceeds %d bytes", maxHandoffBytes)
	}
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncating secret handoff: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seeking secret handoff: %w", err)
	}
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("writing secret handoff: %w", err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, requiredSeals); err != nil {
		return fmt.Errorf("sealing secret handoff: %w", err)
	}
	return nil
}

func ReadHandoff(file *os.File, configDigest string, expected []string) (Store, error) {
	if file == nil {
		return nil, fmt.Errorf("secret handoff file is required")
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return nil, fmt.Errorf("reading secret handoff seals: %w", err)
	}
	if seals&requiredSeals != requiredSeals {
		return nil, fmt.Errorf("secret handoff is not sealed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking secret handoff: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxHandoffBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading secret handoff: %w", err)
	}
	if len(data) > maxHandoffBytes {
		return nil, fmt.Errorf("secret handoff exceeds %d bytes", maxHandoffBytes)
	}
	var payload handoff
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decoding secret handoff: %w", err)
	}
	if payload.Version != handoffVersion {
		return nil, fmt.Errorf("unsupported secret handoff version %d", payload.Version)
	}
	if payload.ConfigDigest != configDigest {
		return nil, fmt.Errorf("secret handoff config digest mismatch")
	}
	want := slices.Clone(expected)
	slices.Sort(want)
	got := make([]string, 0, len(payload.Secrets))
	for name, value := range payload.Secrets {
		if value == "" || value == "null" {
			return nil, fmt.Errorf("secret handoff contains unresolved secret %q", name)
		}
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		return nil, fmt.Errorf("secret handoff names do not match verified config")
	}
	return Store(payload.Secrets), nil
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
