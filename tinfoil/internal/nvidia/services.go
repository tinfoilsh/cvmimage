package nvidia

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/nvml"
)

const (
	persistencedUID     = 143
	persistencedGID     = 143
	serviceReadyWait    = 30 * time.Second
	servicePollInterval = 500 * time.Millisecond
	maxPIDFileSize      = 32
)

type nvmlAPI interface {
	Init() nvml.Return
	DeviceGetCount() (int, nvml.Return)
	Shutdown() nvml.Return
}

type servicePaths struct {
	persistencedRun  string
	persistencedPID  string
	persistencedSock string
	fabricRun        string
	fabricPID        string
	fabricSock       string
	cdiSpec          string
}

var systemServicePaths = servicePaths{
	persistencedRun:  "/run/nvidia-persistenced",
	persistencedPID:  "/run/nvidia-persistenced/nvidia-persistenced.pid",
	persistencedSock: "/run/nvidia-persistenced/socket",
	fabricRun:        "/run/nvidia-fabricmanager",
	fabricPID:        "/run/nvidia-fabricmanager/nv-fabricmanager.pid",
	fabricSock:       "/run/nvidia-fabricmanager/socket",
	cdiSpec:          "/var/run/cdi/nvidia.yaml",
}

// Services provides fixed, execution-free NVIDIA userspace readiness and
// publication contracts. Process paths, arguments, and ordering belong to the
// bootstrap orchestrator.
type Services struct {
	paths        servicePaths
	nvml         nvmlAPI
	persistUID   int
	persistGID   int
	readyWait    time.Duration
	pollInterval time.Duration
}

// NewServices creates the production NVIDIA userspace service helpers.
func NewServices() *Services {
	return newServices(nvml.New())
}

func newServices(api nvmlAPI) *Services {
	return &Services{
		paths:        systemServicePaths,
		nvml:         api,
		persistUID:   persistencedUID,
		persistGID:   persistencedGID,
		readyWait:    serviceReadyWait,
		pollInterval: servicePollInterval,
	}
}

// PreparePersistencedRuntime creates the measured 143:143 runtime directory
// and removes stale PID and socket files without following unexpected types.
func (s *Services) PreparePersistencedRuntime() error {
	if err := os.MkdirAll(s.paths.persistencedRun, 0755); err != nil {
		return fmt.Errorf("create nvidia-persistenced runtime: %w", err)
	}
	info, err := os.Lstat(s.paths.persistencedRun)
	if err != nil {
		return fmt.Errorf("inspect nvidia-persistenced runtime: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("nvidia-persistenced runtime %s is not a directory", s.paths.persistencedRun)
	}
	if err := os.Chown(s.paths.persistencedRun, s.persistUID, s.persistGID); err != nil {
		return fmt.Errorf("chown nvidia-persistenced runtime: %w", err)
	}
	if err := os.Chmod(s.paths.persistencedRun, 0755); err != nil {
		return fmt.Errorf("chmod nvidia-persistenced runtime: %w", err)
	}
	if err := removeRuntimeState(s.paths.persistencedPID, false); err != nil {
		return fmt.Errorf("remove stale nvidia-persistenced PID: %w", err)
	}
	if err := removeRuntimeState(s.paths.persistencedSock, true); err != nil {
		return fmt.Errorf("remove stale nvidia-persistenced socket: %w", err)
	}
	return nil
}

// PrepareFabricManagerRuntime creates the fixed Fabric Manager runtime
// directory and removes stale PID and socket files without executing helpers
// or following unexpected types.
func (s *Services) PrepareFabricManagerRuntime() error {
	if err := os.MkdirAll(s.paths.fabricRun, 0755); err != nil {
		return fmt.Errorf("create NVIDIA Fabric Manager runtime: %w", err)
	}
	info, err := os.Lstat(s.paths.fabricRun)
	if err != nil {
		return fmt.Errorf("inspect NVIDIA Fabric Manager runtime: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("NVIDIA Fabric Manager runtime %s is not a directory", s.paths.fabricRun)
	}
	if err := os.Chmod(s.paths.fabricRun, 0755); err != nil {
		return fmt.Errorf("chmod NVIDIA Fabric Manager runtime: %w", err)
	}
	if err := removeRuntimeState(s.paths.fabricPID, false); err != nil {
		return fmt.Errorf("remove stale NVIDIA Fabric Manager PID: %w", err)
	}
	if err := removeRuntimeState(s.paths.fabricSock, true); err != nil {
		return fmt.Errorf("remove stale NVIDIA Fabric Manager socket: %w", err)
	}
	return nil
}

// WaitForPersistenced waits for the fixed nvidia-persistenced Unix socket.
func (s *Services) WaitForPersistenced(ctx context.Context) error {
	return s.waitForService(ctx, "nvidia-persistenced", s.paths.persistencedPID, s.paths.persistencedSock)
}

// WaitForFabricManager waits for the fixed Fabric Manager Unix socket. Fabric
// Manager runs in the foreground under the PID1 supervisor, so it does not
// publish a PID file.
func (s *Services) WaitForFabricManager(ctx context.Context) error {
	return s.waitForService(ctx, "NVIDIA Fabric Manager", "", s.paths.fabricSock)
}

func (s *Services) waitForService(ctx context.Context, name, pidPath, socketPath string) error {
	waitCtx, cancel := context.WithTimeout(ctx, s.readyWait)
	defer cancel()

	var lastErr error
	for {
		lastErr = validateServiceReadiness(name, pidPath, socketPath)
		if lastErr == nil {
			return nil
		}
		if err := waitPoll(waitCtx, s.pollInterval); err != nil {
			return fmt.Errorf("%s readiness failed (%v): %w", name, lastErr, err)
		}
	}
}

func validateServiceReadiness(name, pidPath, socketPath string) error {
	if pidPath != "" {
		if err := validateLivePID(pidPath); err != nil {
			return fmt.Errorf("validate %s PID: %w", name, err)
		}
	}
	if err := validateUnixSocket(socketPath); err != nil {
		return fmt.Errorf("validate %s socket: %w", name, err)
	}
	return nil
}

// WaitForNVML polls go-nvml directly until it reports exactly expected GPUs.
// Every successful Init is paired with Shutdown before the next poll or return.
func (s *Services) WaitForNVML(ctx context.Context, expected int) error {
	if expected < 1 {
		return fmt.Errorf("invalid expected GPU count %d", expected)
	}
	if s.nvml == nil {
		return errors.New("NVML is not configured")
	}
	waitCtx, cancel := context.WithTimeout(ctx, s.readyWait)
	defer cancel()

	var lastErr error
	for {
		lastErr = probeNVML(s.nvml, expected)
		if lastErr == nil {
			return nil
		}
		if err := waitPoll(waitCtx, s.pollInterval); err != nil {
			return fmt.Errorf("NVIDIA NVML readiness failed (%v): %w", lastErr, err)
		}
	}
}

func probeNVML(api nvmlAPI, expected int) error {
	if result := api.Init(); result != nvml.SUCCESS {
		return fmt.Errorf("initialize NVML: %s", nvml.ErrorString(result))
	}
	count, countResult := api.DeviceGetCount()
	shutdownResult := api.Shutdown()
	if countResult != nvml.SUCCESS {
		return fmt.Errorf("query NVML device count: %s", nvml.ErrorString(countResult))
	}
	if shutdownResult != nvml.SUCCESS {
		return fmt.Errorf("shutdown NVML: %s", nvml.ErrorString(shutdownResult))
	}
	if count != expected {
		return fmt.Errorf("NVML reported %d GPUs, want %d", count, expected)
	}
	return nil
}

// CreateCDITemporary creates an empty same-directory temporary file for the
// bootstrap orchestrator to populate with the fixed CDI generator contract.
func (s *Services) CreateCDITemporary() (string, error) {
	directory := filepath.Dir(s.paths.cdiSpec)
	if err := ensureDirectory(directory); err != nil {
		return "", fmt.Errorf("prepare NVIDIA CDI directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".nvidia.*.yaml")
	if err != nil {
		return "", fmt.Errorf("create NVIDIA CDI temporary file: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close NVIDIA CDI temporary file: %w", err)
	}
	return path, nil
}

// PublishCDI validates, syncs, and atomically renames a same-directory regular
// nonempty temporary file over the fixed CDI destination, then syncs its
// directory. Validation failures leave the existing destination untouched.
func (s *Services) PublishCDI(temporary string) error {
	destination := filepath.Clean(s.paths.cdiSpec)
	temporary = filepath.Clean(temporary)
	directory := filepath.Dir(destination)
	if filepath.Dir(temporary) != directory || temporary == destination {
		return fmt.Errorf("NVIDIA CDI temporary file %s is not a distinct same-directory file", temporary)
	}

	fd, err := unix.Open(temporary, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open NVIDIA CDI temporary file: %w", err)
	}
	file := os.NewFile(uintptr(fd), temporary)
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", temporary)
	}
	if err == nil && info.Size() == 0 {
		err = fmt.Errorf("%s is empty", temporary)
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		pathInfo, pathErr := os.Lstat(temporary)
		if pathErr != nil {
			err = pathErr
		} else if !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
			err = fmt.Errorf("%s changed during validation", temporary)
		}
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("validate NVIDIA CDI temporary file: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close NVIDIA CDI temporary file: %w", closeErr)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("publish NVIDIA CDI specification: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync NVIDIA CDI directory: %w", err)
	}
	return nil
}

func removeRuntimeState(path string, socket bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	valid := info.Mode().IsRegular()
	if socket {
		valid = info.Mode()&os.ModeSocket != 0
	}
	if !valid {
		return fmt.Errorf("%s has unexpected type %s", path, info.Mode().Type())
	}
	return os.Remove(path)
}

func validateLivePID(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPIDFileSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxPIDFileSize {
		return fmt.Errorf("%s exceeds %d bytes", path, maxPIDFileSize)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return fmt.Errorf("%s contains an empty PID", path)
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return fmt.Errorf("%s contains invalid PID %q", path, value)
		}
	}
	pid, err := strconv.ParseInt(value, 10, 32)
	if err != nil || pid < 1 {
		return fmt.Errorf("%s contains invalid PID %q", path, value)
	}
	if err := unix.Kill(int(pid), 0); err != nil {
		return fmt.Errorf("PID %d is not live: %w", pid, err)
	}
	return nil
}

func validateUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a Unix socket", path)
	}
	return nil
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func waitPoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
