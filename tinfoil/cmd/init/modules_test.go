package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type loadedRuntimeModule struct {
	path       string
	compressed bool
	params     string
}

func withRuntimeModuleMocks(t *testing.T, loaded map[string]bool, files map[string]bool, loader func(string, bool, string) error) {
	withRuntimeModuleMocksAndContents(t, loaded, files, nil, loader)
}

func withRuntimeModuleMocksAndContents(t *testing.T, loaded map[string]bool, files map[string]bool, fileContents map[string]string, loader func(string, bool, string) error) {
	t.Helper()

	oldRoot := runtimeKernelModulesRoot
	oldReleasePath := runtimeKernelReleasePath
	oldSysfsRoot := runtimeModuleSysfsRoot
	oldStat := runtimeModuleStat
	oldReadFile := readRuntimeModuleFile
	oldReadRelease := readRuntimeKernelRelease
	oldFinit := finitRuntimeModule
	t.Cleanup(func() {
		runtimeKernelModulesRoot = oldRoot
		runtimeKernelReleasePath = oldReleasePath
		runtimeModuleSysfsRoot = oldSysfsRoot
		runtimeModuleStat = oldStat
		readRuntimeModuleFile = oldReadFile
		readRuntimeKernelRelease = oldReadRelease
		finitRuntimeModule = oldFinit
	})

	runtimeKernelModulesRoot = "/modules"
	runtimeKernelReleasePath = "/proc/sys/kernel/osrelease"
	runtimeModuleSysfsRoot = "/sys/module"
	readRuntimeKernelRelease = func() (string, error) { return "7.0.0-test", nil }
	runtimeModuleStat = func(path string) (os.FileInfo, error) {
		if strings.HasPrefix(path, "/sys/module/") {
			if loaded[filepath.Base(path)] {
				return nil, nil
			}
			return nil, os.ErrNotExist
		}
		if files[path] {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	readRuntimeModuleFile = func(path string) ([]byte, error) {
		if fileContents != nil {
			if content, ok := fileContents[path]; ok {
				return []byte(content), nil
			}
		}
		if files[path] {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	finitRuntimeModule = loader
}

func TestLoadDockerKernelModulesLoadsFixedClosure(t *testing.T) {
	loaded := map[string]bool{}
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/fs/overlayfs/not-selected.ko.zst":  true,
		"/modules/7.0.0-test/kernel/net/bridge/not-selected.ko.zst":    true,
		"/modules/7.0.0-test/kernel/net/netfilter/not-selected.ko.zst": true,
	}
	wantPaths := []string{
		"kernel/fs/overlayfs/overlay.ko.zst",
		"kernel/net/sched/sch_fq_codel.ko.zst",
		"kernel/drivers/net/veth.ko.zst",
		"kernel/net/llc/llc.ko.zst",
		"kernel/net/802/stp.ko.zst",
		"kernel/net/bridge/bridge.ko.zst",
		"kernel/net/bridge/br_netfilter.ko.zst",
		"kernel/net/netfilter/x_tables.ko.zst",
		"kernel/net/netfilter/nfnetlink.ko.zst",
		"kernel/net/ipv4/netfilter/nf_defrag_ipv4.ko.zst",
		"kernel/net/ipv6/netfilter/nf_defrag_ipv6.ko.zst",
		"kernel/net/netfilter/nf_conntrack.ko.zst",
		"kernel/net/netfilter/nf_conntrack_netlink.ko.zst",
		"kernel/net/netfilter/nf_nat.ko.zst",
		"kernel/net/netfilter/nf_tables.ko.zst",
		"kernel/net/netfilter/nft_ct.ko.zst",
		"kernel/net/netfilter/nft_chain_nat.ko.zst",
		"kernel/net/netfilter/nft_compat.ko.zst",
		"kernel/net/netfilter/xt_tcpudp.ko.zst",
		"kernel/net/netfilter/xt_addrtype.ko.zst",
		"kernel/net/netfilter/xt_conntrack.ko.zst",
		"kernel/net/netfilter/xt_nat.ko.zst",
		"kernel/net/netfilter/xt_MASQUERADE.ko.zst",
	}
	for _, rel := range wantPaths {
		files["/modules/7.0.0-test/"+rel] = true
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocks(t, loaded, files, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		moduleNeedles := []struct {
			needle string
			name   string
		}{
			{"/overlay.ko", "overlay"},
			{"/sch_fq_codel.ko", "sch_fq_codel"},
			{"/veth.ko", "veth"},
			{"/llc.ko", "llc"},
			{"/stp.ko", "stp"},
			{"/bridge.ko", "bridge"},
			{"/br_netfilter.ko", "br_netfilter"},
			{"/x_tables.ko", "x_tables"},
			{"/nfnetlink.ko", "nfnetlink"},
			{"/nf_defrag_ipv4.ko", "nf_defrag_ipv4"},
			{"/nf_defrag_ipv6.ko", "nf_defrag_ipv6"},
			{"/nf_conntrack.ko", "nf_conntrack"},
			{"/nf_conntrack_netlink.ko", "nf_conntrack_netlink"},
			{"/nf_nat.ko", "nf_nat"},
			{"/nf_tables.ko", "nf_tables"},
			{"/nft_ct.ko", "nft_ct"},
			{"/nft_chain_nat.ko", "nft_chain_nat"},
			{"/nft_compat.ko", "nft_compat"},
			{"/xt_tcpudp.ko", "xt_tcpudp"},
			{"/xt_addrtype.ko", "xt_addrtype"},
			{"/xt_conntrack.ko", "xt_conntrack"},
			{"/xt_nat.ko", "xt_nat"},
			{"/xt_MASQUERADE.ko", "xt_MASQUERADE"},
		}
		for _, module := range moduleNeedles {
			if strings.Contains(path, module.needle) {
				loaded[module.name] = true
				return nil
			}
		}
		t.Fatalf("unexpected module path %s", path)
		return nil
	})

	if err := loadDockerKernelModules(); err != nil {
		t.Fatalf("loadDockerKernelModules: %v", err)
	}

	var want []loadedRuntimeModule
	for _, rel := range wantPaths {
		want = append(want, loadedRuntimeModule{path: "/modules/7.0.0-test/" + rel, compressed: true})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadNVIDIAPrerequisiteKernelModulesLoadsAESNI(t *testing.T) {
	loaded := map[string]bool{}
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/arch/x86/crypto/aesni-intel.ko.zst":         true,
		"/modules/7.0.0-test/kernel/arch/x86/crypto/ghash-clmulni-intel.ko.zst": true,
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocks(t, loaded, files, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		if strings.Contains(path, "/aesni-intel.ko") {
			loaded["aesni_intel"] = true
			return nil
		}
		t.Fatalf("unexpected module path %s", path)
		return nil
	})

	if err := loadNVIDIAPrerequisiteKernelModules(); err != nil {
		t.Fatalf("loadNVIDIAPrerequisiteKernelModules: %v", err)
	}

	want := []loadedRuntimeModule{
		{path: "/modules/7.0.0-test/kernel/arch/x86/crypto/aesni-intel.ko.zst", compressed: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadNVIDIACoreKernelModulesLoadsFixedClosureWithParams(t *testing.T) {
	loaded := map[string]bool{}
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/crypto/ecdsa_generic.ko.zst": true,
		"/modules/7.0.0-test/kernel/crypto/ecdh_generic.ko.zst":  true,
		"/modules/7.0.0-test/updates/dkms/nvidia.ko":             true,
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocks(t, loaded, files, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		switch filepath.Base(path) {
		case "ecdh_generic.ko.zst":
			loaded["ecdh_generic"] = true
		case "ecdsa_generic.ko.zst":
			loaded["ecdsa_generic"] = true
		case "nvidia.ko":
			loaded["nvidia"] = true
		default:
			t.Fatalf("unexpected module path %s", path)
		}
		return nil
	})

	if err := loadNVIDIACoreKernelModules(); err != nil {
		t.Fatalf("loadNVIDIACoreKernelModules: %v", err)
	}

	want := []loadedRuntimeModule{
		{path: "/modules/7.0.0-test/kernel/crypto/ecdh_generic.ko.zst", compressed: true},
		{path: "/modules/7.0.0-test/kernel/crypto/ecdsa_generic.ko.zst", compressed: true},
		{path: "/modules/7.0.0-test/updates/dkms/nvidia.ko", params: nvidiaKernelModuleParams},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadNVIDIAUVMKernelModulesLoadsOnlyMissingUVMWhenCoreLoaded(t *testing.T) {
	loaded := map[string]bool{"nvidia": true}
	files := map[string]bool{
		"/modules/7.0.0-test/updates/dkms/nvidia.ko":     true,
		"/modules/7.0.0-test/updates/dkms/nvidia-uvm.ko": true,
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocks(t, loaded, files, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		if filepath.Base(path) != "nvidia-uvm.ko" {
			t.Fatalf("unexpected module path %s", path)
		}
		loaded["nvidia_uvm"] = true
		return nil
	})

	if err := loadNVIDIAUVMKernelModules(); err != nil {
		t.Fatalf("loadNVIDIAUVMKernelModules: %v", err)
	}

	want := []loadedRuntimeModule{
		{path: "/modules/7.0.0-test/updates/dkms/nvidia-uvm.ko"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadNVIDIAModesetKernelModulesLoadsFixedClosure(t *testing.T) {
	loaded := map[string]bool{"nvidia": true}
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/drivers/platform/wmi/wmi.ko.zst": true,
		"/modules/7.0.0-test/kernel/drivers/acpi/video.ko.zst":       true,
		"/modules/7.0.0-test/updates/dkms/nvidia-modeset.ko":         true,
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocks(t, loaded, files, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		switch filepath.Base(path) {
		case "wmi.ko.zst":
			loaded["wmi"] = true
		case "video.ko.zst":
			loaded["video"] = true
		case "nvidia-modeset.ko":
			loaded["nvidia_modeset"] = true
		default:
			t.Fatalf("unexpected module path %s", path)
		}
		return nil
	})

	if err := loadNVIDIAModesetKernelModules(); err != nil {
		t.Fatalf("loadNVIDIAModesetKernelModules: %v", err)
	}

	want := []loadedRuntimeModule{
		{path: "/modules/7.0.0-test/kernel/drivers/platform/wmi/wmi.ko.zst", compressed: true},
		{path: "/modules/7.0.0-test/kernel/drivers/acpi/video.ko.zst", compressed: true},
		{path: "/modules/7.0.0-test/updates/dkms/nvidia-modeset.ko"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadRuntimeKernelModuleSkipsAlreadyLoaded(t *testing.T) {
	withRuntimeModuleMocks(t, map[string]bool{"overlay": true}, nil, func(path string, compressed bool, params string) error {
		t.Fatalf("finit_module should not be called for an already loaded module")
		return nil
	})

	if err := loadRuntimeKernelModule("7.0.0-test", runtimeKernelModule{
		name:  "overlay",
		paths: []string{"kernel/fs/overlayfs/overlay.ko.zst"},
	}); err != nil {
		t.Fatalf("loadRuntimeKernelModule: %v", err)
	}
}

func TestLoadRuntimeKernelModuleSkipsExactBuiltIn(t *testing.T) {
	files := map[string]bool{}
	contents := map[string]string{
		"/modules/7.0.0-test/modules.builtin": strings.Join([]string{
			"kernel/fs/overlayfs/overlay.ko",
			"kernel/net/bridge/bridge.ko",
			"",
		}, "\n"),
	}
	withRuntimeModuleMocksAndContents(t, map[string]bool{}, files, contents, func(path string, compressed bool, params string) error {
		t.Fatalf("finit_module should not be called for a built-in module")
		return nil
	})

	if err := loadRuntimeKernelModule("7.0.0-test", runtimeKernelModule{
		name: "overlay",
		paths: []string{
			"kernel/fs/overlayfs/overlay.ko.zst",
			"kernel/fs/overlayfs/overlay.ko",
		},
	}); err != nil {
		t.Fatalf("loadRuntimeKernelModule: %v", err)
	}
}

func TestLoadRuntimeKernelModuleIgnoresUnboundedBuiltIn(t *testing.T) {
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/fs/overlayfs/overlay.ko.zst": true,
	}
	contents := map[string]string{
		"/modules/7.0.0-test/modules.builtin": "kernel/drivers/net/wireless/untrusted.ko\n",
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocksAndContents(t, map[string]bool{}, files, contents, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		return nil
	})

	if err := loadRuntimeKernelModule("7.0.0-test", runtimeKernelModule{
		name:  "overlay",
		paths: []string{"kernel/fs/overlayfs/overlay.ko.zst"},
	}); err != nil {
		t.Fatalf("loadRuntimeKernelModule: %v", err)
	}
	want := []loadedRuntimeModule{{path: "/modules/7.0.0-test/kernel/fs/overlayfs/overlay.ko.zst", compressed: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadRuntimeKernelModuleFallsBackToUncompressed(t *testing.T) {
	loaded := map[string]bool{}
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/fs/overlayfs/overlay.ko": true,
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocks(t, loaded, files, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		loaded["overlay"] = true
		return nil
	})

	if err := loadRuntimeKernelModule("7.0.0-test", runtimeKernelModule{
		name: "overlay",
		paths: []string{
			"kernel/fs/overlayfs/overlay.ko.zst",
			"kernel/fs/overlayfs/overlay.ko",
		},
	}); err != nil {
		t.Fatalf("loadRuntimeKernelModule: %v", err)
	}
	want := []loadedRuntimeModule{{path: "/modules/7.0.0-test/kernel/fs/overlayfs/overlay.ko", compressed: false}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadNVIDIACoreKernelModulesSkipsBuiltInECDSA(t *testing.T) {
	loaded := map[string]bool{}
	files := map[string]bool{
		"/modules/7.0.0-test/updates/dkms/nvidia.ko": true,
	}
	contents := map[string]string{
		"/modules/7.0.0-test/modules.builtin": "kernel/crypto/ecdh_generic.ko\nkernel/crypto/ecdsa_generic.ko\n",
	}
	var got []loadedRuntimeModule
	withRuntimeModuleMocksAndContents(t, loaded, files, contents, func(path string, compressed bool, params string) error {
		got = append(got, loadedRuntimeModule{path: path, compressed: compressed, params: params})
		if filepath.Base(path) != "nvidia.ko" {
			t.Fatalf("unexpected module path %s", path)
		}
		loaded["nvidia"] = true
		return nil
	})

	if err := loadNVIDIACoreKernelModules(); err != nil {
		t.Fatalf("loadNVIDIACoreKernelModules: %v", err)
	}
	want := []loadedRuntimeModule{
		{path: "/modules/7.0.0-test/updates/dkms/nvidia.ko", params: nvidiaKernelModuleParams},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded modules = %#v, want %#v", got, want)
	}
}

func TestLoadRuntimeKernelModuleAcceptsAlreadyExists(t *testing.T) {
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/fs/overlayfs/overlay.ko.zst": true,
	}
	withRuntimeModuleMocks(t, map[string]bool{}, files, func(path string, compressed bool, params string) error {
		return unix.EEXIST
	})

	if err := loadRuntimeKernelModule("7.0.0-test", runtimeKernelModule{
		name:  "overlay",
		paths: []string{"kernel/fs/overlayfs/overlay.ko.zst"},
	}); err != nil {
		t.Fatalf("loadRuntimeKernelModule: %v", err)
	}
}

func TestLoadRuntimeKernelModuleReportsFinitFailure(t *testing.T) {
	files := map[string]bool{
		"/modules/7.0.0-test/kernel/fs/overlayfs/overlay.ko.zst": true,
	}
	withRuntimeModuleMocks(t, map[string]bool{}, files, func(path string, compressed bool, params string) error {
		return errors.New("bad vermagic")
	})

	err := loadRuntimeKernelModule("7.0.0-test", runtimeKernelModule{
		name:  "overlay",
		paths: []string{"kernel/fs/overlayfs/overlay.ko.zst"},
	})
	if err == nil {
		t.Fatal("loadRuntimeKernelModule unexpectedly succeeded")
	}
	for _, want := range []string{"overlay", "finit_module", "bad vermagic"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestLoadRuntimeKernelModuleRejectsBroadModuleCandidate(t *testing.T) {
	withRuntimeModuleMocks(t, map[string]bool{}, map[string]bool{}, func(path string, compressed bool, params string) error {
		t.Fatal("finit_module should not be attempted for an invalid candidate")
		return nil
	})

	err := loadRuntimeKernelModule("7.0.0-test", runtimeKernelModule{
		name:  "escape",
		paths: []string{"kernel/net/bridge/../drivers/evil.ko"},
	})
	if err == nil {
		t.Fatal("loadRuntimeKernelModule accepted a traversal candidate")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("error %q does not report traversal", err)
	}
}

func TestRuntimeKernelModuleLoadedRejectsInvalidNames(t *testing.T) {
	withRuntimeModuleMocks(t, map[string]bool{"overlay": true}, nil, func(path string, compressed bool, params string) error {
		return fmt.Errorf("unexpected finit_module")
	})
	for _, name := range []string{"", "../overlay", "net/overlay"} {
		if runtimeKernelModuleLoaded(name) {
			t.Fatalf("runtimeKernelModuleLoaded(%q) = true", name)
		}
	}
	if !runtimeKernelModuleLoaded("overlay") {
		t.Fatalf("runtimeKernelModuleLoaded did not see mocked overlay")
	}
}
