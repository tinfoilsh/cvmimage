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
	}}
	var want []mountCall
	names := append([]string{"null", "tdx_guest", "sev-guest"}, gpuDeviceFixture()...)
	for _, name := range names {
		source := filepath.Join(attestationDeviceSource, name)
		kind := devicePathNode
		flags := uintptr(unix.MS_BIND)
		if name == "nvidia-caps" {
			kind = devicePathDirectory
			flags |= unix.MS_REC
		}
		kernel.kinds[source] = kind
		want = append(want, mountCall{source: source, target: "/dev/" + name, flags: flags})
	}
	if err := restrictServiceFilesystems(kernel, true); err != nil {
		t.Fatalf("restrictServiceFilesystems: %v", err)
	}

	var bindings []mountCall
	for _, call := range kernel.calls {
		if strings.HasPrefix(call.source, attestationDeviceSource+"/") {
			bindings = append(bindings, call)
		}
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
