package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	pidFileLimit        = 32
)

type serviceInstance struct {
	pid  int
	file *os.File
	info os.FileInfo
}

func (instance *serviceInstance) close() {
	if instance != nil {
		_ = instance.file.Close()
	}
}

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

func freezeFromPIDFile(path string) (*serviceInstance, error) {
	instance, err := openServiceInstance(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := signalProcessGroup(instance.pid, syscall.SIGSTOP); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			instance.close()
			return nil, nil
		}
		instance.close()
		return nil, fmt.Errorf("freezing pid %d process group: %w", instance.pid, err)
	}
	return instance, nil
}

func restartFrozenFromPIDFile(ctx context.Context, path string, instance *serviceInstance) error {
	if instance == nil {
		return nil
	}
	if err := signalProcessGroup(instance.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("killing frozen pid %d process group: %w", instance.pid, err)
	}
	return waitForReplacementPID(ctx, path, instance)
}

func openServiceInstance(path string) (*serviceInstance, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, pidFileLimit+1))
	if err != nil {
		file.Close()
		return nil, err
	}
	if len(data) > pidFileLimit {
		file.Close()
		return nil, fmt.Errorf("%s exceeds %d bytes", path, pidFileLimit)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		file.Close()
		return nil, fmt.Errorf("invalid pid in %s", path)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &serviceInstance{pid: pid, file: file, info: info}, nil
}

func restartFromPIDFile(ctx context.Context, path string) error {
	instance, err := openServiceInstance(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer instance.close()
	if err := signalProcessGroup(instance.pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signaling pid %d process group: %w", instance.pid, err)
	}
	return waitForReplacementPID(ctx, path, instance)
}

func signalProcessGroup(pid int, signal syscall.Signal) error {
	return syscall.Kill(-pid, signal)
}

func waitForReplacementPID(ctx context.Context, path string, previous *serviceInstance) error {
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
			restarted, err := replacementPIDAvailable(path, previous)
			if err != nil {
				return err
			}
			if restarted {
				return nil
			}
		}
	}
}

func replacementPIDAvailable(path string, previous *serviceInstance) (bool, error) {
	current, err := openServiceInstance(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer current.close()
	return !os.SameFile(previous.info, current.info), nil
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
