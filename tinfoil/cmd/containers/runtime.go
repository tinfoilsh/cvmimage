package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
	"tinfoil/internal/runtimeconfig"
)

const (
	restartWaitTimeout  = 15 * time.Second
	restartPollInterval = 100 * time.Millisecond
)

func loadRuntimeConfig() (*runtimeconfig.Config, error) {
	data, err := os.ReadFile(boot.RuntimeConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var config runtimeconfig.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func writeRuntimeArtifacts(config *runtimeconfig.Config, source []byte) error {
	if err := atomicWrite(boot.RuntimeConfigPath, source, 0o600); err != nil {
		return err
	}
	shimYAML, err := yaml.Marshal(config.ShimCfg)
	if err != nil {
		return err
	}
	if err := atomicWrite(boot.ShimConfigPath, shimYAML, 0o644); err != nil {
		return err
	}
	type egressEntry struct {
		Allow []string `yaml:"allow"`
	}
	type egressConfig struct {
		Networks map[string]egressEntry `yaml:"networks"`
	}
	egress := egressConfig{Networks: map[string]egressEntry{}}
	for name, network := range config.Networks {
		if network != nil && network.Egress == "allowlist" {
			egress.Networks[name] = egressEntry{Allow: network.Allow}
		}
	}
	data, err := yaml.Marshal(egress)
	if err != nil {
		return err
	}
	return atomicWrite(boot.EgressConfigPath, data, 0o600)
}

func restartRuntimeServices(ctx context.Context) error {
	var errs []error
	for _, path := range []string{boot.ShimPIDPath} {
		if err := restartFromPIDFile(ctx, path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func freezeFromPIDFile(path string) (int, error) {
	pid, err := readPIDFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return 0, nil
		}
		return 0, fmt.Errorf("freezing pid %d: %w", pid, err)
	}
	return pid, nil
}

func restartFrozenFromPIDFile(ctx context.Context, path string, pid int) error {
	if pid == 0 {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("killing frozen pid %d: %w", pid, err)
	}
	return waitForReplacementPID(ctx, path, pid)
}

func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("invalid pid in %s", path)
	}
	return pid, nil
}

func restartFromPIDFile(ctx context.Context, path string) error {
	oldPID, err := readPIDFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := syscall.Kill(oldPID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signaling pid %d: %w", oldPID, err)
	}
	return waitForReplacementPID(ctx, path, oldPID)
}

func waitForReplacementPID(ctx context.Context, path string, oldPID int) error {
	deadline := time.NewTimer(restartWaitTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(restartPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("waiting for %s to restart", path)
		case <-ticker.C:
			restarted, err := replacementPIDAvailable(path, oldPID)
			if err != nil {
				return err
			}
			if restarted {
				return nil
			}
		}
	}
}

func replacementPIDAvailable(path string, oldPID int) (bool, error) {
	current, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	newPID, err := strconv.Atoi(strings.TrimSpace(string(current)))
	return err == nil && newPID > 1 && newPID != oldPID, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".runtime-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
