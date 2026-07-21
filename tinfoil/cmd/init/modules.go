package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type runtimeKernelModule struct {
	name   string
	paths  []string
	params string
}

var (
	nvidiaKernelModuleParams = strings.Join([]string{
		"NVreg_TemporaryFilePath=/var/tmp",
		"NVreg_EnableS0ixPowerManagement=1",
		"NVreg_PreserveVideoMemoryAllocations=1",
	}, " ")

	nvidiaCoreModule = runtimeKernelModule{
		name: "nvidia",
		paths: []string{
			"updates/dkms/nvidia.ko.zst",
			"updates/dkms/nvidia.ko",
		},
		params: nvidiaKernelModuleParams,
	}

	nvidiaPrerequisiteKernelModules = []runtimeKernelModule{
		{
			name: "aesni_intel",
			paths: []string{
				"kernel/arch/x86/crypto/aesni-intel.ko.zst",
				"kernel/arch/x86/crypto/aesni-intel.ko",
			},
		},
	}

	nvidiaCoreKernelModules = []runtimeKernelModule{
		// NVIDIA CC SPDM needs kernel ECDSA and ECDH (see the historical
		// nvidia-lkca.conf modprobe hook this replaces). On the stock Ubuntu
		// kernel ecdh_generic is builtin (modules.builtin) and this entry
		// no-ops; listing it pins the dependency so a kernel that ships it
		// modular gets it loaded before nvidia. Note the NVIDIA bootstrap
		// treats a failed core-module load as a warning (the same image also
		// boots CPU-only CVMs), so a GPU image whose kernel truly lacks ECDH
		// surfaces the failure downstream at GPU attestation, not here.
		{
			name: "ecdh_generic",
			paths: []string{
				"kernel/crypto/ecdh_generic.ko.zst",
				"kernel/crypto/ecdh_generic.ko",
			},
		},
		{
			name: "ecdsa_generic",
			paths: []string{
				"kernel/crypto/ecdsa_generic.ko.zst",
				"kernel/crypto/ecdsa_generic.ko",
			},
		},
		nvidiaCoreModule,
	}

	nvidiaUVMKernelModules = []runtimeKernelModule{
		nvidiaCoreModule,
		{
			name: "nvidia_uvm",
			paths: []string{
				"updates/dkms/nvidia-uvm.ko.zst",
				"updates/dkms/nvidia-uvm.ko",
			},
		},
	}

	nvidiaModesetKernelModules = []runtimeKernelModule{
		nvidiaCoreModule,
		{
			name: "wmi",
			paths: []string{
				"kernel/drivers/platform/wmi/wmi.ko.zst",
				"kernel/drivers/platform/wmi/wmi.ko",
			},
		},
		{
			name: "video",
			paths: []string{
				"kernel/drivers/acpi/video.ko.zst",
				"kernel/drivers/acpi/video.ko",
			},
		},
		{
			name: "nvidia_modeset",
			paths: []string{
				"updates/dkms/nvidia-modeset.ko.zst",
				"updates/dkms/nvidia-modeset.ko",
			},
		},
	}

	dockerKernelModules = []runtimeKernelModule{
		{
			name: "overlay",
			paths: []string{
				"kernel/fs/overlayfs/overlay.ko.zst",
				"kernel/fs/overlayfs/overlay.ko",
			},
		},
		{
			name: "sch_fq_codel",
			paths: []string{
				"kernel/net/sched/sch_fq_codel.ko.zst",
				"kernel/net/sched/sch_fq_codel.ko",
			},
		},
		{
			name: "veth",
			paths: []string{
				"kernel/drivers/net/veth.ko.zst",
				"kernel/drivers/net/veth.ko",
			},
		},
		{
			name: "llc",
			paths: []string{
				"kernel/net/llc/llc.ko.zst",
				"kernel/net/llc/llc.ko",
			},
		},
		{
			name: "stp",
			paths: []string{
				"kernel/net/802/stp.ko.zst",
				"kernel/net/802/stp.ko",
			},
		},
		{
			name: "bridge",
			paths: []string{
				"kernel/net/bridge/bridge.ko.zst",
				"kernel/net/bridge/bridge.ko",
			},
		},
		{
			name: "br_netfilter",
			paths: []string{
				"kernel/net/bridge/br_netfilter.ko.zst",
				"kernel/net/bridge/br_netfilter.ko",
			},
		},
		{
			name: "x_tables",
			paths: []string{
				"kernel/net/netfilter/x_tables.ko.zst",
				"kernel/net/netfilter/x_tables.ko",
			},
		},
		{
			name: "nfnetlink",
			paths: []string{
				"kernel/net/netfilter/nfnetlink.ko.zst",
				"kernel/net/netfilter/nfnetlink.ko",
			},
		},
		{
			name: "nf_defrag_ipv4",
			paths: []string{
				"kernel/net/ipv4/netfilter/nf_defrag_ipv4.ko.zst",
				"kernel/net/ipv4/netfilter/nf_defrag_ipv4.ko",
			},
		},
		{
			name: "nf_defrag_ipv6",
			paths: []string{
				"kernel/net/ipv6/netfilter/nf_defrag_ipv6.ko.zst",
				"kernel/net/ipv6/netfilter/nf_defrag_ipv6.ko",
			},
		},
		{
			name: "nf_conntrack",
			paths: []string{
				"kernel/net/netfilter/nf_conntrack.ko.zst",
				"kernel/net/netfilter/nf_conntrack.ko",
			},
		},
		{
			name: "nf_conntrack_netlink",
			paths: []string{
				"kernel/net/netfilter/nf_conntrack_netlink.ko.zst",
				"kernel/net/netfilter/nf_conntrack_netlink.ko",
			},
		},
		{
			name: "nf_nat",
			paths: []string{
				"kernel/net/netfilter/nf_nat.ko.zst",
				"kernel/net/netfilter/nf_nat.ko",
			},
		},
		{
			name: "nf_tables",
			paths: []string{
				"kernel/net/netfilter/nf_tables.ko.zst",
				"kernel/net/netfilter/nf_tables.ko",
			},
		},
		{
			name: "nft_ct",
			paths: []string{
				"kernel/net/netfilter/nft_ct.ko.zst",
				"kernel/net/netfilter/nft_ct.ko",
			},
		},
		{
			name: "nft_chain_nat",
			paths: []string{
				"kernel/net/netfilter/nft_chain_nat.ko.zst",
				"kernel/net/netfilter/nft_chain_nat.ko",
			},
		},
		{
			name: "nft_compat",
			paths: []string{
				"kernel/net/netfilter/nft_compat.ko.zst",
				"kernel/net/netfilter/nft_compat.ko",
			},
		},
		{
			name: "xt_tcpudp",
			paths: []string{
				"kernel/net/netfilter/xt_tcpudp.ko.zst",
				"kernel/net/netfilter/xt_tcpudp.ko",
			},
		},
		{
			name: "xt_addrtype",
			paths: []string{
				"kernel/net/netfilter/xt_addrtype.ko.zst",
				"kernel/net/netfilter/xt_addrtype.ko",
			},
		},
		{
			name: "xt_conntrack",
			paths: []string{
				"kernel/net/netfilter/xt_conntrack.ko.zst",
				"kernel/net/netfilter/xt_conntrack.ko",
			},
		},
		{
			name: "xt_nat",
			paths: []string{
				"kernel/net/netfilter/xt_nat.ko.zst",
				"kernel/net/netfilter/xt_nat.ko",
			},
		},
		{
			name: "xt_MASQUERADE",
			paths: []string{
				"kernel/net/netfilter/xt_MASQUERADE.ko.zst",
				"kernel/net/netfilter/xt_MASQUERADE.ko",
			},
		},
	}

	runtimeKernelModulesRoot = "/usr/lib/modules"
	runtimeKernelReleasePath = "/proc/sys/kernel/osrelease"
	runtimeModuleSysfsRoot   = "/sys/module"
	runtimeModuleStat        = os.Stat
	readRuntimeModuleFile    = os.ReadFile
	readRuntimeKernelRelease = func() (string, error) {
		data, err := os.ReadFile(runtimeKernelReleasePath)
		if err != nil {
			return "", err
		}
		release := strings.TrimSpace(string(data))
		if release == "" {
			return "", fmt.Errorf("%s is empty", runtimeKernelReleasePath)
		}
		return release, nil
	}
	finitRuntimeModule = func(path string, compressed bool, params string) error {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		flags := 0
		if compressed {
			flags = unix.MODULE_INIT_COMPRESSED_FILE
		}
		return unix.FinitModule(int(file.Fd()), params, flags)
	}
)

func loadDockerKernelModules() error {
	return loadRuntimeKernelModuleClosure("docker", dockerKernelModules)
}

func loadNVIDIAPrerequisiteKernelModules() error {
	return loadRuntimeKernelModuleClosure("nvidia-prerequisite", nvidiaPrerequisiteKernelModules)
}

func loadNVIDIACoreKernelModules() error {
	return loadRuntimeKernelModuleClosure("nvidia-core", nvidiaCoreKernelModules)
}

func loadNVIDIAUVMKernelModules() error {
	return loadRuntimeKernelModuleClosure("nvidia-uvm", nvidiaUVMKernelModules)
}

func loadNVIDIAModesetKernelModules() error {
	return loadRuntimeKernelModuleClosure("nvidia-modeset", nvidiaModesetKernelModules)
}

func loadRuntimeKernelModuleClosure(name string, modules []runtimeKernelModule) error {
	release, err := readRuntimeKernelRelease()
	if err != nil {
		return fmt.Errorf("read kernel release for %s module closure: %w", name, err)
	}
	for _, module := range modules {
		if err := loadRuntimeKernelModule(release, module); err != nil {
			return fmt.Errorf("%s module closure: %w", name, err)
		}
	}
	return nil
}

func loadRuntimeKernelModule(release string, module runtimeKernelModule) error {
	if runtimeKernelModuleLoaded(module.name) {
		return nil
	}
	if runtimeKernelModuleBuiltIn(release, module) {
		initLogf("runtime module built in: %s", module.name)
		return nil
	}

	var missing []string
	for _, rel := range module.paths {
		if err := validateRuntimeKernelModulePath(rel); err != nil {
			return fmt.Errorf("%s has invalid bounded module candidate %q: %w", module.name, rel, err)
		}
		path := filepath.Join(runtimeKernelModulesRoot, release, rel)
		if _, err := runtimeModuleStat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				missing = append(missing, path)
				continue
			}
			return fmt.Errorf("%s stat %s: %w", module.name, path, err)
		}
		err := finitRuntimeModule(path, strings.HasSuffix(path, ".ko.zst"), module.params)
		if err == nil || errors.Is(err, unix.EEXIST) || runtimeKernelModuleLoaded(module.name) {
			initLogf("runtime module loaded: %s", module.name)
			return nil
		}
		return fmt.Errorf("%s finit_module %s: %w", module.name, path, err)
	}

	if runtimeKernelModuleLoaded(module.name) {
		return nil
	}
	return fmt.Errorf("no bounded module candidate for %s under %s (missing: %s)", module.name, filepath.Join(runtimeKernelModulesRoot, release), strings.Join(missing, ", "))
}

func runtimeKernelModuleLoaded(name string) bool {
	if name == "" || filepath.Base(name) != name || strings.Contains(name, string(os.PathSeparator)) {
		return false
	}
	_, err := runtimeModuleStat(filepath.Join(runtimeModuleSysfsRoot, name))
	return err == nil
}

func runtimeKernelModuleBuiltIn(release string, module runtimeKernelModule) bool {
	if module.name == "" || filepath.Base(module.name) != module.name || strings.Contains(module.name, string(os.PathSeparator)) {
		return false
	}
	builtinPath := filepath.Join(runtimeKernelModulesRoot, release, "modules.builtin")
	data, err := readRuntimeModuleFile(builtinPath)
	if err != nil {
		return false
	}
	allowedBuiltins := map[string]struct{}{}
	for _, rel := range module.paths {
		if err := validateRuntimeKernelModulePath(rel); err != nil {
			return false
		}
		allowedBuiltins[strings.TrimSuffix(rel, ".zst")] = struct{}{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if _, ok := allowedBuiltins[line]; ok {
			return true
		}
	}
	return false
}

func validateRuntimeKernelModulePath(rel string) error {
	if rel == "" {
		return errors.New("empty path")
	}
	if filepath.IsAbs(rel) {
		return errors.New("absolute path")
	}
	clean := filepath.Clean(rel)
	if clean != rel || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return errors.New("path traversal")
	}
	if !(strings.HasSuffix(clean, ".ko") || strings.HasSuffix(clean, ".ko.zst")) {
		return errors.New("not a kernel module")
	}
	return nil
}
