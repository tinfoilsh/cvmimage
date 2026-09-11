package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"tinfoil/inference/internal/nvidia"
	"tinfoil/internal/pid1/supervisor"
	"tinfoil/pid1"
)

type nvidiaBootstrapControl interface {
	GPUCount() (int, error)
	HasNVSwitch() (bool, error)
	HoldGPUEnableReferences() error
	EnableGPURuntimePowerManagement() error
	LoadCoreKernelModules() error
	WaitForCoreDeviceNodes(context.Context, int) error
	PreparePersistencedRuntime() error
	WaitForPersistenced(context.Context) error
	LoadUVMKernelModules() error
	WaitForUVMDeviceNodes(context.Context, int) error
	LoadModesetKernelModules() error
	DetectFabricMode() (nvidia.FabricMode, error)
	PrepareFabricManagerRuntime() error
	WaitForFabricManager(context.Context) error
	WaitForNVML(context.Context, int) error
	CreateCDITemporary() (string, error)
	PublishCDI(string) error
}

type systemNVIDIA struct {
	services *nvidia.Services
}

func newSystemNVIDIA() *systemNVIDIA {
	return &systemNVIDIA{services: nvidia.NewServices()}
}

func (*systemNVIDIA) GPUCount() (int, error)     { return nvidia.GPUCount() }
func (*systemNVIDIA) HasNVSwitch() (bool, error) { return nvidia.HasNVSwitch() }
func (*systemNVIDIA) HoldGPUEnableReferences() error {
	return nvidia.HoldGPUEnableReferences()
}
func (*systemNVIDIA) EnableGPURuntimePowerManagement() error {
	return nvidia.EnableGPURuntimePowerManagement()
}
func (*systemNVIDIA) LoadCoreKernelModules() error { return nvidia.LoadCoreKernelModules() }
func (*systemNVIDIA) WaitForCoreDeviceNodes(ctx context.Context, expectedGPUs int) error {
	return waitForNVIDIADeviceNodes(ctx, func() error {
		return nvidia.SetupCoreDeviceNodes(expectedGPUs)
	}, nvidiaDeviceWait, nvidiaDevicePoll)
}
func (s *systemNVIDIA) PreparePersistencedRuntime() error {
	return s.services.PreparePersistencedRuntime()
}
func (s *systemNVIDIA) WaitForPersistenced(ctx context.Context) error {
	return s.services.WaitForPersistenced(ctx)
}
func (*systemNVIDIA) LoadUVMKernelModules() error { return nvidia.LoadUVMKernelModules() }
func (*systemNVIDIA) WaitForUVMDeviceNodes(ctx context.Context, expectedGPUs int) error {
	return waitForNVIDIADeviceNodes(ctx, func() error {
		return nvidia.SetupUVMDeviceNodes(expectedGPUs)
	}, nvidiaDeviceWait, nvidiaDevicePoll)
}
func (*systemNVIDIA) LoadModesetKernelModules() error {
	return nvidia.LoadModesetKernelModules()
}
func (*systemNVIDIA) DetectFabricMode() (nvidia.FabricMode, error) {
	return nvidia.DetectFabricMode()
}
func (s *systemNVIDIA) PrepareFabricManagerRuntime() error {
	return s.services.PrepareFabricManagerRuntime()
}
func (s *systemNVIDIA) WaitForFabricManager(ctx context.Context) error {
	return s.services.WaitForFabricManager(ctx)
}
func (s *systemNVIDIA) WaitForNVML(ctx context.Context, count int) error {
	return s.services.WaitForNVML(ctx, count)
}
func (s *systemNVIDIA) CreateCDITemporary() (string, error) {
	return s.services.CreateCDITemporary()
}
func (s *systemNVIDIA) PublishCDI(path string) error { return s.services.PublishCDI(path) }

func runNVIDIABootstrap(
	ctx context.Context,
	control nvidiaBootstrapControl,
	oneShot func(context.Context, supervisor.Command) error,
	startService func(context.Context, supervisor.Service) error,
	writeStatus func(nvidia.BootstrapStatus) error,
) error {
	gpuCount, err := control.GPUCount()
	if err == nil && gpuCount == 0 {
		var hasSwitch bool
		hasSwitch, err = control.HasNVSwitch()
		if err == nil && !hasSwitch {
			return writeStatus(nvidia.NoGPUBootstrapStatus())
		}
		if err == nil {
			err = errors.New("NVIDIA NVSwitch topology has no detected GPUs")
		}
	}
	if err == nil {
		err = runNVIDIABootstrapSteps(ctx, control, oneShot, startService, gpuCount)
	}
	if err != nil {
		pid1.Logf("NVIDIA bootstrap failed: %v", err)
		if statusErr := writeStatus(nvidia.FailedBootstrapStatus()); statusErr != nil {
			return fmt.Errorf("persist failed NVIDIA bootstrap status after %v: %w", err, statusErr)
		}
		return nil
	}
	if err := writeStatus(nvidia.ReadyBootstrapStatus(gpuCount)); err != nil {
		return fmt.Errorf("persist ready NVIDIA bootstrap status: %w", err)
	}
	return nil
}

func runNVIDIABootstrapSteps(
	ctx context.Context,
	control nvidiaBootstrapControl,
	oneShot func(context.Context, supervisor.Command) error,
	startService func(context.Context, supervisor.Service) error,
	gpuCount int,
) error {
	if gpuCount < 1 {
		return fmt.Errorf("invalid detected NVIDIA GPU count %d", gpuCount)
	}
	if err := control.HoldGPUEnableReferences(); err != nil {
		return fmt.Errorf("hold NVIDIA PCI enable references: %w", err)
	}
	if err := control.EnableGPURuntimePowerManagement(); err != nil {
		return fmt.Errorf("enable NVIDIA runtime power management: %w", err)
	}
	if err := control.LoadCoreKernelModules(); err != nil {
		return fmt.Errorf("load NVIDIA core kernel modules: %w", err)
	}
	if err := control.WaitForCoreDeviceNodes(ctx, gpuCount); err != nil {
		return fmt.Errorf("set up NVIDIA core device nodes: %w", err)
	}
	if err := control.PreparePersistencedRuntime(); err != nil {
		return fmt.Errorf("prepare nvidia-persistenced runtime: %w", err)
	}
	persistenced, fabric := nvidiaServices(control)
	if err := startService(ctx, persistenced.Process()); err != nil {
		return fmt.Errorf("start nvidia-persistenced: %w", err)
	}
	if err := control.LoadUVMKernelModules(); err != nil {
		return fmt.Errorf("load NVIDIA UVM kernel modules: %w", err)
	}
	if err := control.WaitForUVMDeviceNodes(ctx, gpuCount); err != nil {
		return fmt.Errorf("set up NVIDIA UVM device nodes: %w", err)
	}
	if err := control.LoadModesetKernelModules(); err != nil {
		return fmt.Errorf("load NVIDIA modeset kernel modules: %w", err)
	}
	if err := control.WaitForUVMDeviceNodes(ctx, gpuCount); err != nil {
		return fmt.Errorf("set up NVIDIA modeset device nodes: %w", err)
	}
	fabricMode, err := control.DetectFabricMode()
	if err != nil {
		var nvl5 *nvidia.ErrNVL5RequiresNVLSM
		if errors.As(err, &nvl5) {
			return nvl5
		}
		return fmt.Errorf("detect NVIDIA fabric mode: %w", err)
	}
	switch fabricMode {
	case nvidia.FabricModeNone:
	case nvidia.FabricModeFabricManager:
		if err := control.PrepareFabricManagerRuntime(); err != nil {
			return fmt.Errorf("prepare NVIDIA Fabric Manager runtime: %w", err)
		}
		if err := startService(ctx, fabric.Process()); err != nil {
			return fmt.Errorf("start NVIDIA Fabric Manager: %w", err)
		}
	default:
		return fmt.Errorf("unsupported NVIDIA fabric mode %d", fabricMode)
	}
	if err := control.WaitForNVML(ctx, gpuCount); err != nil {
		return fmt.Errorf("wait for NVIDIA NVML: %w", err)
	}
	temporary, err := control.CreateCDITemporary()
	if err != nil {
		return fmt.Errorf("create NVIDIA CDI temporary file: %w", err)
	}
	defer os.Remove(temporary)
	cdiCtx, cancelCDI := context.WithTimeout(ctx, cdiGenerateLimit)
	defer cancelCDI()
	if err := oneShot(cdiCtx, pid1.Command(
		"nvidia-ctk-cdi",
		"/usr/bin/nvidia-ctk",
		"cdi", "generate", "--output="+temporary,
	)); err != nil {
		return fmt.Errorf("generate NVIDIA CDI specification: %w", err)
	}
	if err := control.PublishCDI(temporary); err != nil {
		return fmt.Errorf("publish NVIDIA CDI specification: %w", err)
	}
	return nil
}

func waitForNVIDIADeviceNodes(
	ctx context.Context,
	setup func() error,
	limit time.Duration,
	poll time.Duration,
) error {
	waitCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	var lastErr error
	for {
		if err := setup(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		timer := time.NewTimer(poll)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return fmt.Errorf("NVIDIA device readiness failed (%v): %w", lastErr, waitCtx.Err())
		case <-timer.C:
		}
	}
}

func fabricManagerCommand() supervisor.Command {
	cmd := pid1.Command(
		fabricManagerName,
		"/usr/bin/nv-fabricmanager",
		"-c", fabricConfigPath,
	)
	env := make([]string, 0, len(cmd.Env))
	for _, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		if key != "FM_CONFIG_FILE" && key != "FM_PID_FILE" {
			env = append(env, entry)
		}
	}
	cmd.Env = env
	return cmd
}
