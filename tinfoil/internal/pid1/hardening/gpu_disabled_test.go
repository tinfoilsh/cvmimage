//go:build !tinfoil_gpu

package hardening

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCPUAttestationViewExcludesGPUDevices(t *testing.T) {
	kernel := &fakeFilesystemKernel{kinds: map[string]devicePathKind{
		filepath.Join(attestationDeviceSource, "sev-guest"): devicePathNode,
		filepath.Join(attestationDeviceSource, "nvidia0"):   devicePathNode,
		filepath.Join(attestationDeviceSource, "nvidiactl"): devicePathNode,
	}}
	if err := restrictServiceFilesystems(kernel, true); err != nil {
		t.Fatal(err)
	}
	var hasSNP bool
	for _, call := range kernel.calls {
		if strings.Contains(call.target, "nvidia") {
			t.Fatalf("GPU device exposed: %s", call.target)
		}
		if call.target == "/dev/sev-guest" {
			hasSNP = true
		}
	}
	if !hasSNP {
		t.Fatal("SNP report device missing")
	}
}
