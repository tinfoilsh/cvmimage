package main

import (
	"slices"
	"strings"
	"testing"

	"tinfoil/internal/attestation"
	"tinfoil/internal/runtimeconfig"
)

func TestValidateGPUSecurity(t *testing.T) {
	const unknownDeviceID = 0xffff
	h100 := []uint64{gpuDeviceIDH100}
	h100SXM := []uint64{gpuDeviceIDH100SXM}
	h200 := []uint64{gpuDeviceIDH200}
	b200 := []uint64{gpuDeviceIDB200}
	b300 := []uint64{gpuDeviceIDB300}
	for _, test := range []struct {
		name       string
		deviceIDs  []uint64
		allow      bool
		wantArch   string
		wantSwitch bool
		wantErr    string
	}{
		{name: "single H100", deviceIDs: h100, wantArch: attestation.GPUArchHopper},
		{name: "single H100 SXM", deviceIDs: h100SXM, wantArch: attestation.GPUArchHopper},
		{name: "single H200", deviceIDs: h200, wantArch: attestation.GPUArchHopper},
		{name: "multiple H100 default", deviceIDs: slices.Repeat(h100, hopperGPUCount), wantErr: "security.allow-unencrypted-nvlink: true"},
		{name: "multiple H100 opt-in", deviceIDs: slices.Repeat(h100, hopperGPUCount), allow: true, wantArch: attestation.GPUArchHopper, wantSwitch: true},
		{name: "multiple H100 SXM default", deviceIDs: slices.Repeat(h100SXM, hopperGPUCount), wantErr: "security.allow-unencrypted-nvlink: true"},
		{name: "multiple H100 SXM opt-in", deviceIDs: slices.Repeat(h100SXM, hopperGPUCount), allow: true, wantArch: attestation.GPUArchHopper, wantSwitch: true},
		{name: "multiple H200 default", deviceIDs: slices.Repeat(h200, hopperGPUCount), wantErr: "security.allow-unencrypted-nvlink: true"},
		{name: "multiple H200 opt-in", deviceIDs: slices.Repeat(h200, hopperGPUCount), allow: true, wantArch: attestation.GPUArchHopper, wantSwitch: true},
		{name: "two Hopper default", deviceIDs: slices.Repeat(h200, 2), wantErr: "security.allow-unencrypted-nvlink: true"},
		{name: "single B200", deviceIDs: b200, wantArch: attestation.GPUArchBlackwell},
		{name: "single B300", deviceIDs: b300, wantArch: attestation.GPUArchBlackwell},
		{name: "multiple B200 default", deviceIDs: slices.Repeat(b200, maxGPUCount), wantArch: attestation.GPUArchBlackwell},
		{name: "multiple B300 default", deviceIDs: slices.Repeat(b300, maxGPUCount), wantArch: attestation.GPUArchBlackwell},
		{name: "multiple Blackwell opt-in", deviceIDs: slices.Repeat(b200, maxGPUCount), allow: true, wantArch: attestation.GPUArchBlackwell},
		{name: "missing devices", wantErr: "no GPUs detected"},
		{name: "unknown device opt-in", deviceIDs: []uint64{unknownDeviceID}, allow: true, wantErr: "unsupported PCI device ID"},
		{name: "multiple unknown devices", deviceIDs: slices.Repeat([]uint64{unknownDeviceID}, maxGPUCount), wantErr: "unsupported PCI device ID"},
		{name: "unknown last device", deviceIDs: []uint64{gpuDeviceIDB200, unknownDeviceID}, allow: true, wantErr: "GPU 1 has unsupported PCI device ID"},
		{name: "unknown first device", deviceIDs: []uint64{unknownDeviceID, gpuDeviceIDB300}, wantErr: "GPU 0 has unsupported PCI device ID"},
		{name: "mixed architectures", deviceIDs: []uint64{gpuDeviceIDB200, gpuDeviceIDH200}, wantErr: "mixed GPU architectures"},
		{name: "mixed architectures opt-in", deviceIDs: []uint64{gpuDeviceIDH200, gpuDeviceIDB300}, allow: true, wantErr: "mixed GPU architectures"},
	} {
		t.Run(test.name, func(t *testing.T) {
			arch, err := validateGPUSecurity(test.deviceIDs, len(test.deviceIDs), test.allow)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) || arch != "" {
					t.Fatalf("validateGPUSecurity = %q, %v; want rejection containing %q", arch, err, test.wantErr)
				}
				return
			}
			if err != nil || arch != test.wantArch {
				t.Fatalf("validateGPUSecurity = %q, %v; want %q", arch, err, test.wantArch)
			}
			needSwitch, err := attestation.RequiresNVSwitchEvidence(arch, len(test.deviceIDs))
			if err != nil {
				t.Fatal(err)
			}
			if needSwitch != test.wantSwitch {
				t.Fatalf("NVSwitch evidence required = %v, want %v", needSwitch, test.wantSwitch)
			}
		})
	}
}

func TestGPUSecurityRejectsCountMismatch(t *testing.T) {
	for _, deviceIDs := range [][]uint64{
		{gpuDeviceIDB200},
		slices.Repeat([]uint64{gpuDeviceIDB200}, maxGPUCount+1),
	} {
		arch, err := validateGPUSecurity(deviceIDs, maxGPUCount, true)
		if err == nil || !strings.Contains(err.Error(), "GPUs, detected") || arch != "" {
			t.Fatalf("validateGPUSecurity = %q, %v; want GPU count mismatch", arch, err)
		}
	}
}

func TestMeasuredGPUSecurityPolicy(t *testing.T) {
	const configYAML = `
cvm-version: 0.14.12
cpus: 8
memory: 16384
gpus: 8
shim:
  upstream-port: 8080
  dummy-attestation: true
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`
	for _, test := range []struct {
		name    string
		fields  string
		allowed bool
	}{
		{name: "omitted"},
		{name: "false", fields: "security:\n  allow-unencrypted-nvlink: false\n"},
		{name: "true", fields: "security:\n  allow-unencrypted-nvlink: true\n", allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := runtimeconfig.Decode([]byte(configYAML+test.fields), false)
			if err != nil {
				t.Fatal(err)
			}
			deviceIDs := slices.Repeat([]uint64{gpuDeviceIDH200}, config.GPUs)
			_, err = validateGPUSecurity(deviceIDs, config.GPUs, config.Security.AllowUnencryptedNVLink)
			if (err == nil) != test.allowed {
				t.Fatalf("policy error = %v, want allowed = %v", err, test.allowed)
			}
		})
	}
}
