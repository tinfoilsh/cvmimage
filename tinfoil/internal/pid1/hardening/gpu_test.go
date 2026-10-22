//go:build tinfoil_gpu

package hardening

import (
	"golang.org/x/sys/unix"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
