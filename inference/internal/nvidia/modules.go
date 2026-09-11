// Package nvidia owns the fixed policy and mechanisms needed to initialize
// NVIDIA hardware in a Tinfoil CVM.
package nvidia

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	nvidiaModuleRoot = "/usr/lib/tinfoil/kernel-modules"
	moduleSysfsRoot  = "/sys/module"

	nvidiaCoreParameters = "NVreg_TemporaryFilePath=/var/tmp " +
		"NVreg_EnableS0ixPowerManagement=1 " +
		"NVreg_PreserveVideoMemoryAllocations=1"
)

type modulePolicy struct {
	kernelName string
	fileName   string
	parameters string
}

var (
	coreModule = modulePolicy{
		kernelName: "nvidia",
		fileName:   "nvidia.ko",
		parameters: nvidiaCoreParameters,
	}
	uvmModule = modulePolicy{
		kernelName: "nvidia_uvm",
		fileName:   "nvidia-uvm.ko",
	}
	modesetModule = modulePolicy{
		kernelName: "nvidia_modeset",
		fileName:   "nvidia-modeset.ko",
	}
)

type dependencies struct {
	moduleRoot      string
	moduleSysfsRoot string
	stat            func(string) (os.FileInfo, error)
	finitModule     func(string, string, int) error
}

// LoadCoreKernelModules loads the fixed NVIDIA core module inventory.
func LoadCoreKernelModules() error {
	return loadInventory("core", systemDependencies(), coreModule)
}

// LoadUVMKernelModules loads the fixed NVIDIA core and UVM module inventory.
func LoadUVMKernelModules() error {
	return loadInventory("UVM", systemDependencies(), coreModule, uvmModule)
}

// LoadModesetKernelModules loads the fixed NVIDIA core and modeset inventory.
func LoadModesetKernelModules() error {
	return loadInventory("modeset", systemDependencies(), coreModule, modesetModule)
}

func systemDependencies() dependencies {
	return dependencies{
		moduleRoot:      nvidiaModuleRoot,
		moduleSysfsRoot: moduleSysfsRoot,
		stat:            os.Stat,
		finitModule:     finitModule,
	}
}

func loadInventory(name string, deps dependencies, inventory ...modulePolicy) error {
	for _, policy := range inventory {
		if err := loadModule(policy, deps); err != nil {
			return fmt.Errorf("load NVIDIA %s modules: %w", name, err)
		}
	}
	return nil
}

func loadModule(policy modulePolicy, deps dependencies) error {
	loaded, err := moduleLoaded(policy.kernelName, deps)
	if err != nil {
		return fmt.Errorf("check whether %s is loaded: %w", policy.kernelName, err)
	}
	if loaded {
		return nil
	}

	path, err := fixedModulePath(deps.moduleRoot, policy.fileName)
	if err != nil {
		return fmt.Errorf("resolve fixed path for %s: %w", policy.kernelName, err)
	}
	if _, err := deps.stat(path); err != nil {
		return fmt.Errorf("%s stat %s: %w", policy.kernelName, path, err)
	}

	err = deps.finitModule(path, policy.parameters, 0)
	if err == nil || errors.Is(err, unix.EEXIST) {
		return nil
	}
	return fmt.Errorf("%s finit_module %s: %w", policy.kernelName, path, err)
}

func fixedModulePath(root, candidate string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("invalid fixed NVIDIA module root")
	}
	if !fixedNVIDIACandidate(candidate) {
		return "", fmt.Errorf("invalid fixed NVIDIA candidate %q", candidate)
	}

	path := filepath.Join(root, candidate)
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("resolve NVIDIA module path: %w", err)
	}
	if relative != candidate {
		return "", errors.New("NVIDIA module path escaped fixed module root")
	}
	return path, nil
}

func fixedNVIDIACandidate(candidate string) bool {
	switch candidate {
	case "nvidia.ko", "nvidia-uvm.ko", "nvidia-modeset.ko":
		return true
	default:
		return false
	}
}

func moduleLoaded(name string, deps dependencies) (bool, error) {
	_, err := deps.stat(filepath.Join(deps.moduleSysfsRoot, name))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func finitModule(path, parameters string, flags int) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return unix.FinitModule(int(file.Fd()), parameters, flags)
}
