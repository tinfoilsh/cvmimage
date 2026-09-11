package nvidia

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maxBootstrapStatusSize = 40

var (
	bootstrapNoGPU  = []byte("tinfoil-nvidia-bootstrap-v1:no-gpu\n")
	bootstrapFailed = []byte("tinfoil-nvidia-bootstrap-v1:failed\n")
	bootstrapReady  = [...][]byte{
		nil,
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:1\n"),
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:2\n"),
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:3\n"),
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:4\n"),
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:5\n"),
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:6\n"),
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:7\n"),
		[]byte("tinfoil-nvidia-bootstrap-v1:ready:8\n"),
	}
)

type BootstrapState uint8

const (
	BootstrapStateNoGPU BootstrapState = iota + 1
	BootstrapStateReady
	BootstrapStateFailed
)

type BootstrapStatus struct {
	State    BootstrapState
	GPUCount int
}

func NoGPUBootstrapStatus() BootstrapStatus {
	return BootstrapStatus{State: BootstrapStateNoGPU}
}

func ReadyBootstrapStatus(gpuCount int) BootstrapStatus {
	return BootstrapStatus{State: BootstrapStateReady, GPUCount: gpuCount}
}

func FailedBootstrapStatus() BootstrapStatus {
	return BootstrapStatus{State: BootstrapStateFailed}
}

func WriteBootstrapStatus(path string, status BootstrapStatus) error {
	encoded, err := encodeBootstrapStatus(status)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("create NVIDIA bootstrap status directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".nvidia-bootstrap-status.*")
	if err != nil {
		return fmt.Errorf("create NVIDIA bootstrap status temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("chmod NVIDIA bootstrap status temporary file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write NVIDIA bootstrap status: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync NVIDIA bootstrap status: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close NVIDIA bootstrap status: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish NVIDIA bootstrap status: %w", err)
	}
	removeTemporary = false
	if err := syncBootstrapStatusDirectory(directory); err != nil {
		return fmt.Errorf("sync NVIDIA bootstrap status directory: %w", err)
	}
	return nil
}

func ReadBootstrapStatus(path string) (BootstrapStatus, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return BootstrapStatus{}, fmt.Errorf("open NVIDIA bootstrap status: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return BootstrapStatus{}, fmt.Errorf("inspect NVIDIA bootstrap status: %w", err)
	}
	if !info.Mode().IsRegular() {
		return BootstrapStatus{}, fmt.Errorf("NVIDIA bootstrap status is not a regular file")
	}
	if info.Size() > maxBootstrapStatusSize {
		return BootstrapStatus{}, fmt.Errorf("NVIDIA bootstrap status exceeds %d bytes", maxBootstrapStatusSize)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxBootstrapStatusSize+1))
	if err != nil {
		return BootstrapStatus{}, fmt.Errorf("read NVIDIA bootstrap status: %w", err)
	}
	if len(encoded) > maxBootstrapStatusSize {
		return BootstrapStatus{}, fmt.Errorf("NVIDIA bootstrap status exceeds %d bytes", maxBootstrapStatusSize)
	}
	return decodeBootstrapStatus(encoded)
}

func ValidateBootstrapStatus(path string, configuredGPUs int) error {
	status, err := ReadBootstrapStatus(path)
	if err != nil {
		return err
	}
	switch status.State {
	case BootstrapStateFailed:
		return errors.New("NVIDIA bootstrap reported failure")
	case BootstrapStateNoGPU:
		if configuredGPUs != 0 {
			return fmt.Errorf("NVIDIA bootstrap reported no GPUs, config requires %d", configuredGPUs)
		}
	case BootstrapStateReady:
		if configuredGPUs <= 0 {
			return fmt.Errorf("NVIDIA bootstrap reported %d ready GPUs, config requires none", status.GPUCount)
		}
		if status.GPUCount != configuredGPUs {
			return fmt.Errorf("NVIDIA bootstrap reported %d ready GPUs, config requires %d", status.GPUCount, configuredGPUs)
		}
	default:
		return errors.New("invalid NVIDIA bootstrap state")
	}
	return nil
}

func encodeBootstrapStatus(status BootstrapStatus) ([]byte, error) {
	switch status.State {
	case BootstrapStateNoGPU:
		if status.GPUCount != 0 {
			return nil, errors.New("no-GPU NVIDIA bootstrap status has a GPU count")
		}
		return bootstrapNoGPU, nil
	case BootstrapStateReady:
		if status.GPUCount < 1 || status.GPUCount >= len(bootstrapReady) {
			return nil, fmt.Errorf("unsupported NVIDIA bootstrap GPU count %d", status.GPUCount)
		}
		return bootstrapReady[status.GPUCount], nil
	case BootstrapStateFailed:
		if status.GPUCount != 0 {
			return nil, errors.New("failed NVIDIA bootstrap status has a GPU count")
		}
		return bootstrapFailed, nil
	default:
		return nil, errors.New("invalid NVIDIA bootstrap status")
	}
}

func decodeBootstrapStatus(encoded []byte) (BootstrapStatus, error) {
	switch {
	case bytes.Equal(encoded, bootstrapNoGPU):
		return NoGPUBootstrapStatus(), nil
	case bytes.Equal(encoded, bootstrapFailed):
		return FailedBootstrapStatus(), nil
	}
	for gpuCount := 1; gpuCount < len(bootstrapReady); gpuCount++ {
		if bytes.Equal(encoded, bootstrapReady[gpuCount]) {
			return ReadyBootstrapStatus(gpuCount), nil
		}
	}
	return BootstrapStatus{}, errors.New("malformed NVIDIA bootstrap status")
}

func syncBootstrapStatusDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}
