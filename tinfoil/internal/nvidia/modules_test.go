package nvidia

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

type finitCall struct {
	path       string
	parameters string
	flags      int
}

func testDependencies(
	loaded map[string]bool,
	files map[string]bool,
	loader func(string, string, int) error,
) dependencies {
	return dependencies{
		moduleRoot:      "/modules",
		moduleSysfsRoot: "/sys/module",
		stat: func(path string) (os.FileInfo, error) {
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
		},
		finitModule: loader,
	}
}

func loadedName(path string) string {
	switch filepath.Base(path) {
	case "nvidia.ko", "nvidia.ko.zst":
		return "nvidia"
	case "nvidia-uvm.ko", "nvidia-uvm.ko.zst":
		return "nvidia_uvm"
	case "nvidia-modeset.ko", "nvidia-modeset.ko.zst":
		return "nvidia_modeset"
	default:
		return ""
	}
}

func TestFixedInventoriesLoadOnlyOrderedNVIDIAModules(t *testing.T) {
	const coreParameters = "NVreg_TemporaryFilePath=/var/tmp " +
		"NVreg_EnableS0ixPowerManagement=1 " +
		"NVreg_PreserveVideoMemoryAllocations=1"

	tests := []struct {
		name      string
		inventory []modulePolicy
		want      []finitCall
	}{
		{
			name:      "core",
			inventory: []modulePolicy{coreModule},
			want: []finitCall{{
				path:       "/modules/nvidia.ko.zst",
				parameters: coreParameters,
				flags:      unix.MODULE_INIT_COMPRESSED_FILE,
			}},
		},
		{
			name:      "UVM",
			inventory: []modulePolicy{coreModule, uvmModule},
			want: []finitCall{
				{
					path:       "/modules/nvidia.ko.zst",
					parameters: coreParameters,
					flags:      unix.MODULE_INIT_COMPRESSED_FILE,
				},
				{
					path:  "/modules/nvidia-uvm.ko.zst",
					flags: unix.MODULE_INIT_COMPRESSED_FILE,
				},
			},
		},
		{
			name:      "modeset",
			inventory: []modulePolicy{coreModule, modesetModule},
			want: []finitCall{
				{
					path:       "/modules/nvidia.ko.zst",
					parameters: coreParameters,
					flags:      unix.MODULE_INIT_COMPRESSED_FILE,
				},
				{
					path:  "/modules/nvidia-modeset.ko.zst",
					flags: unix.MODULE_INIT_COMPRESSED_FILE,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loaded := map[string]bool{}
			files := map[string]bool{
				"/modules/nvidia.ko.zst":         true,
				"/modules/nvidia-uvm.ko.zst":     true,
				"/modules/nvidia-modeset.ko.zst": true,
				"/modules/not-nvidia.ko.zst":     true,
			}
			var got []finitCall
			deps := testDependencies(loaded, files, func(path, parameters string, flags int) error {
				got = append(got, finitCall{path: path, parameters: parameters, flags: flags})
				name := loadedName(path)
				if name == "" {
					t.Fatalf("attempted to load non-NVIDIA candidate %q", path)
				}
				loaded[name] = true
				return nil
			})

			if err := loadInventory(test.name, deps, test.inventory...); err != nil {
				t.Fatalf("loadInventory: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("finit_module calls = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestFinitModuleCompressionFlagAndCandidateOrder(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]bool
		wantPath  string
		wantFlags int
		wantStats []string
	}{
		{
			name: "compressed preferred",
			files: map[string]bool{
				"/modules/nvidia.ko.zst": true,
				"/modules/nvidia.ko":     true,
			},
			wantPath:  "/modules/nvidia.ko.zst",
			wantFlags: unix.MODULE_INIT_COMPRESSED_FILE,
			wantStats: []string{
				"/modules/nvidia.ko.zst",
			},
		},
		{
			name: "uncompressed fallback",
			files: map[string]bool{
				"/modules/nvidia.ko": true,
			},
			wantPath:  "/modules/nvidia.ko",
			wantFlags: 0,
			wantStats: []string{
				"/modules/nvidia.ko.zst",
				"/modules/nvidia.ko",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotCall finitCall
			var gotStats []string
			deps := testDependencies(map[string]bool{}, test.files, func(path, parameters string, flags int) error {
				gotCall = finitCall{path: path, parameters: parameters, flags: flags}
				return nil
			})
			stat := deps.stat
			deps.stat = func(path string) (os.FileInfo, error) {
				if !strings.HasPrefix(path, "/sys/module/") {
					gotStats = append(gotStats, path)
				}
				return stat(path)
			}

			if err := loadInventory("core", deps, coreModule); err != nil {
				t.Fatalf("loadInventory: %v", err)
			}
			if gotCall.path != test.wantPath || gotCall.flags != test.wantFlags {
				t.Fatalf("finit_module call = %#v, want path %q flags %d", gotCall, test.wantPath, test.wantFlags)
			}
			if !reflect.DeepEqual(gotStats, test.wantStats) {
				t.Fatalf("candidate stat order = %q, want %q", gotStats, test.wantStats)
			}
		})
	}
}

func TestFixedModulePathAllowsOnlyMeasuredInventory(t *testing.T) {
	path, err := fixedModulePath(nvidiaModuleRoot, "nvidia-uvm.ko.zst")
	if err != nil {
		t.Fatalf("fixedModulePath: %v", err)
	}
	const want = "/usr/lib/tinfoil/kernel-modules/nvidia-uvm.ko.zst"
	if path != want {
		t.Fatalf("fixedModulePath = %q, want %q", path, want)
	}

	for _, candidate := range []string{
		"evil.ko",
		"../nvidia.ko",
		"updates/dkms/nvidia.ko",
		"nvidia-drm.ko",
		"nvidia-peermem.ko.zst",
	} {
		t.Run(fmt.Sprintf("candidate_%q", candidate), func(t *testing.T) {
			if _, err := fixedModulePath(nvidiaModuleRoot, candidate); err == nil {
				t.Fatalf("fixedModulePath accepted non-inventory candidate %q", candidate)
			}
		})
	}
	if _, err := fixedModulePath("usr/lib/tinfoil/kernel-modules", "nvidia.ko"); err == nil {
		t.Fatal("fixedModulePath accepted relative module root")
	}
}

func TestAlreadyLoadedModulesAreSafe(t *testing.T) {
	t.Run("loaded before call", func(t *testing.T) {
		deps := testDependencies(map[string]bool{"nvidia": true}, nil, func(string, string, int) error {
			t.Fatal("finit_module called for an already-loaded module")
			return nil
		})
		if err := loadInventory("core", deps, coreModule); err != nil {
			t.Fatalf("loadInventory: %v", err)
		}
	})

	t.Run("finit reports already exists", func(t *testing.T) {
		files := map[string]bool{
			"/modules/nvidia.ko": true,
		}
		deps := testDependencies(map[string]bool{}, files, func(string, string, int) error {
			return unix.EEXIST
		})
		if err := loadInventory("core", deps, coreModule); err != nil {
			t.Fatalf("loadInventory: %v", err)
		}
	})
}

func TestLoadInventoryPropagatesFailuresInOrder(t *testing.T) {
	loadErr := errors.New("bad vermagic")
	files := map[string]bool{
		"/modules/nvidia.ko.zst":     true,
		"/modules/nvidia-uvm.ko.zst": true,
	}
	var calls []string
	deps := testDependencies(map[string]bool{}, files, func(path, _ string, _ int) error {
		calls = append(calls, path)
		return loadErr
	})

	err := loadInventory("UVM", deps, coreModule, uvmModule)
	if err == nil {
		t.Fatal("loadInventory unexpectedly succeeded")
	}
	if !errors.Is(err, loadErr) {
		t.Fatalf("loadInventory error %q does not wrap %q", err, loadErr)
	}
	for _, want := range []string{"load NVIDIA UVM modules", "nvidia", "finit_module", "bad vermagic"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("loadInventory error %q does not contain %q", err, want)
		}
	}
	wantCalls := []string{
		"/modules/nvidia.ko.zst",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("finit_module calls after failure = %q, want %q", calls, wantCalls)
	}
}
