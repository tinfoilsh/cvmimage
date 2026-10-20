package main

import (
	"slices"
	"strings"
	"testing"

	"tinfoil/internal/attestation"
	"tinfoil/internal/nvml"
	"tinfoil/internal/runtimeconfig"
)

func TestValidateGPUSecurity(t *testing.T) {
	const unknownArchitecture nvml.DeviceArchitecture = 0
	hopper := []nvml.DeviceArchitecture{nvml.DEVICE_ARCH_HOPPER}
	blackwell := []nvml.DeviceArchitecture{nvml.DEVICE_ARCH_BLACKWELL}
	for _, test := range []struct {
		name          string
		architectures []nvml.DeviceArchitecture
		allow         bool
		wantArch      string
		wantSwitch    bool
		wantErr       string
	}{
		{name: "single Hopper", architectures: hopper, wantArch: attestation.GPUArchHopper},
		{name: "multiple Hopper default", architectures: slices.Repeat(hopper, hopperGPUCount), wantErr: "security.allow-unencrypted-nvlink: true"},
		{name: "multiple Hopper opt-in", architectures: slices.Repeat(hopper, hopperGPUCount), allow: true, wantArch: attestation.GPUArchHopper, wantSwitch: true},
		{name: "two Hopper default", architectures: slices.Repeat(hopper, 2), wantErr: "security.allow-unencrypted-nvlink: true"},
		{name: "single Blackwell", architectures: blackwell, wantArch: attestation.GPUArchBlackwell},
		{name: "multiple Blackwell default", architectures: slices.Repeat(blackwell, maxGPUCount), wantArch: attestation.GPUArchBlackwell},
		{name: "multiple Blackwell opt-in", architectures: slices.Repeat(blackwell, maxGPUCount), allow: true, wantArch: attestation.GPUArchBlackwell},
		{name: "missing devices", wantErr: "no GPU architectures"},
		{name: "unknown architecture", architectures: []nvml.DeviceArchitecture{unknownArchitecture}, allow: true, wantErr: "unsupported architecture"},
		{name: "unknown last device", architectures: []nvml.DeviceArchitecture{nvml.DEVICE_ARCH_BLACKWELL, unknownArchitecture}, allow: true, wantErr: "GPU 1 has unsupported architecture"},
		{name: "mixed architectures", architectures: []nvml.DeviceArchitecture{nvml.DEVICE_ARCH_BLACKWELL, nvml.DEVICE_ARCH_HOPPER}, wantErr: "mixed GPU architectures"},
		{name: "mixed architectures opt-in", architectures: []nvml.DeviceArchitecture{nvml.DEVICE_ARCH_HOPPER, nvml.DEVICE_ARCH_BLACKWELL}, allow: true, wantErr: "mixed GPU architectures"},
	} {
		t.Run(test.name, func(t *testing.T) {
			arch, err := validateGPUSecurity(test.architectures, test.allow)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) || arch != "" {
					t.Fatalf("validateGPUSecurity = %q, %v; want rejection containing %q", arch, err, test.wantErr)
				}
				return
			}
			if err != nil || arch != test.wantArch {
				t.Fatalf("validateGPUSecurity = %q, %v; want %q", arch, err, test.wantArch)
			}
			needSwitch, err := attestation.RequiresNVSwitchEvidence(arch, len(test.architectures))
			if err != nil {
				t.Fatal(err)
			}
			if needSwitch != test.wantSwitch {
				t.Fatalf("NVSwitch evidence required = %v, want %v", needSwitch, test.wantSwitch)
			}
		})
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
			architectures := slices.Repeat([]nvml.DeviceArchitecture{nvml.DEVICE_ARCH_HOPPER}, config.GPUs)
			_, err = validateGPUSecurity(architectures, config.Security.AllowUnencryptedNVLink)
			if (err == nil) != test.allowed {
				t.Fatalf("policy error = %v, want allowed = %v", err, test.allowed)
			}
		})
	}
}
