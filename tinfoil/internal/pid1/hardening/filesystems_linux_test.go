package hardening

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type mountCall struct {
	source         string
	target         string
	filesystemType string
	flags          uintptr
	data           string
}

type fakeFilesystemKernel struct {
	failAt int
	err    error
	steps  int
	calls  []mountCall
	kinds  map[string]devicePathKind
	paths  []string
}

func (kernel *fakeFilesystemKernel) step() error {
	kernel.steps++
	if kernel.failAt == kernel.steps {
		return kernel.err
	}
	return nil
}

func (kernel *fakeFilesystemKernel) unshare(flags int) error {
	kernel.calls = append(kernel.calls, mountCall{source: "unshare", flags: uintptr(flags)})
	return kernel.step()
}

func (kernel *fakeFilesystemKernel) mount(source, target, filesystemType string, flags uintptr, data string) error {
	kernel.calls = append(kernel.calls, mountCall{
		source:         source,
		target:         target,
		filesystemType: filesystemType,
		flags:          flags,
		data:           data,
	})
	return kernel.step()
}

func (kernel *fakeFilesystemKernel) unmount(target string, flags int) error {
	return kernel.step()
}
func (kernel *fakeFilesystemKernel) pathKind(path string) (devicePathKind, error) {
	return kernel.kinds[path], kernel.step()
}
func (kernel *fakeFilesystemKernel) makeTarget(path string, _ devicePathKind) error {
	kernel.paths = append(kernel.paths, "create:"+path)
	return kernel.step()
}
func (kernel *fakeFilesystemKernel) remove(path string) error {
	kernel.paths = append(kernel.paths, "remove:"+path)
	return kernel.step()
}

func TestRestrictServiceFilesystemsUsesFixedPrivateReadOnlyLayout(t *testing.T) {
	kernel := &fakeFilesystemKernel{}
	if err := restrictServiceFilesystems(kernel, false); err != nil {
		t.Fatalf("restrictServiceFilesystems: %v", err)
	}

	baseFlags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	want := []mountCall{
		{source: "unshare", flags: unix.CLONE_NEWNS},
		{target: "/", flags: unix.MS_REC | unix.MS_PRIVATE},
		{source: "proc", target: "/proc", filesystemType: "proc", flags: baseFlags, data: "hidepid=2"},
		{target: "/proc", flags: baseFlags | unix.MS_REMOUNT | unix.MS_RDONLY},
		{source: "tmpfs", target: "/dev", filesystemType: "tmpfs", flags: baseFlags, data: "size=4k,nr_inodes=1,mode=0555"},
		{target: "/dev", flags: baseFlags | unix.MS_REMOUNT | unix.MS_RDONLY},
		{source: "tmpfs", target: "/sys", filesystemType: "tmpfs", flags: baseFlags, data: "size=4k,nr_inodes=1,mode=0555"},
		{target: "/sys", flags: baseFlags | unix.MS_REMOUNT | unix.MS_RDONLY},
	}
	if !reflect.DeepEqual(kernel.calls, want) {
		t.Fatalf("filesystem calls =\n%#v\nwant\n%#v", kernel.calls, want)
	}
}

func TestRestrictServiceFilesystemsFailsClosedAtEveryStep(t *testing.T) {
	for failAt := 1; failAt <= 8; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			stepErr := errors.New("step failed")
			kernel := &fakeFilesystemKernel{failAt: failAt, err: stepErr}
			err := restrictServiceFilesystems(kernel, false)
			if !errors.Is(err, stepErr) {
				t.Fatalf("error = %v, want %v", err, stepErr)
			}
			if len(kernel.calls) != failAt {
				t.Fatalf("calls = %d, want %d", len(kernel.calls), failAt)
			}
		})
	}
}

func TestRestrictShimFilesystemsFailsClosedAtEveryStep(t *testing.T) {
	kinds := map[string]devicePathKind{tdxReportSource: devicePathDirectory}
	for _, relative := range attestationDevicePaths() {
		kind := devicePathNode
		if relative == "nvidia-caps" {
			kind = devicePathDirectory
		}
		kinds[filepath.Join(attestationDeviceSource, relative)] = kind
	}
	baseline := &fakeFilesystemKernel{kinds: kinds}
	if err := restrictServiceFilesystems(baseline, true); err != nil {
		t.Fatalf("baseline restrictServiceFilesystems: %v", err)
	}

	for failAt := 1; failAt <= baseline.steps; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			stepErr := errors.New("step failed")
			kernel := &fakeFilesystemKernel{failAt: failAt, err: stepErr, kinds: kinds}
			err := restrictServiceFilesystems(kernel, true)
			if !errors.Is(err, stepErr) {
				t.Fatalf("error = %v, want %v", err, stepErr)
			}
		})
	}
}

func TestRestrictShimFilesystemsBindsOnlyAttestationDevices(t *testing.T) {
	kernel := &fakeFilesystemKernel{kinds: map[string]devicePathKind{
		tdxReportSource: devicePathDirectory,
		filepath.Join(attestationDeviceSource, "null"):               devicePathNode,
		filepath.Join(attestationDeviceSource, "tdx_guest"):          devicePathNode,
		filepath.Join(attestationDeviceSource, "nvidiactl"):          devicePathNode,
		filepath.Join(attestationDeviceSource, "nvidia0"):            devicePathNode,
		filepath.Join(attestationDeviceSource, "nvidia-caps"):        devicePathDirectory,
		filepath.Join(attestationDeviceSource, "nvidia-nvswitchctl"): devicePathNode,
		filepath.Join(attestationDeviceSource, "nvidia-nvlink"):      devicePathNode,
	}}
	if err := restrictServiceFilesystems(kernel, true); err != nil {
		t.Fatalf("restrictServiceFilesystems: %v", err)
	}

	var bindings []mountCall
	for _, call := range kernel.calls {
		if strings.HasPrefix(call.source, attestationDeviceSource+"/") {
			bindings = append(bindings, call)
		}
	}
	want := []mountCall{
		{source: filepath.Join(attestationDeviceSource, "null"), target: "/dev/null", flags: unix.MS_BIND},
		{source: filepath.Join(attestationDeviceSource, "tdx_guest"), target: "/dev/tdx_guest", flags: unix.MS_BIND},
		{source: filepath.Join(attestationDeviceSource, "nvidiactl"), target: "/dev/nvidiactl", flags: unix.MS_BIND},
		{source: filepath.Join(attestationDeviceSource, "nvidia-caps"), target: "/dev/nvidia-caps", flags: unix.MS_BIND | unix.MS_REC},
		{source: filepath.Join(attestationDeviceSource, "nvidia-nvswitchctl"), target: "/dev/nvidia-nvswitchctl", flags: unix.MS_BIND},
		{source: filepath.Join(attestationDeviceSource, "nvidia-nvlink"), target: "/dev/nvidia-nvlink", flags: unix.MS_BIND},
		{source: filepath.Join(attestationDeviceSource, "nvidia0"), target: "/dev/nvidia0", flags: unix.MS_BIND},
	}
	if !reflect.DeepEqual(bindings, want) {
		t.Fatalf("attestation bindings = %#v, want %#v", bindings, want)
	}

	var foundTDXReport bool
	for _, call := range kernel.calls {
		if call.source == attestationSysSource && call.target == tdxReportSource && call.flags == unix.MS_BIND|unix.MS_REC {
			foundTDXReport = true
		}
	}
	if !foundTDXReport {
		t.Fatalf("TDX report interface was not bound: %#v", kernel.calls)
	}
}

func TestRestrictShimFilesystemsResetsReservedStagingDirectories(t *testing.T) {
	kernel := &fakeFilesystemKernel{kinds: map[string]devicePathKind{
		tdxReportSource: devicePathDirectory,
	}}
	if err := restrictServiceFilesystems(kernel, true); err != nil {
		t.Fatalf("restrictServiceFilesystems: %v", err)
	}

	for _, path := range []string{attestationDeviceSource, attestationSysSource} {
		remove := -1
		create := -1
		for index, operation := range kernel.paths {
			switch operation {
			case "remove:" + path:
				if remove == -1 {
					remove = index
				}
			case "create:" + path:
				if create == -1 {
					create = index
				}
			}
		}
		if remove == -1 || create == -1 || remove > create {
			t.Fatalf("staging operations for %s = %v, want remove before create", path, kernel.paths)
		}
	}
}
