package variant

import (
	"fmt"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"tinfoil/internal/pid1/hardening"
)

func TestInferenceShimRetainsNVIDIADeviceAccess(t *testing.T) {
	want := []string{
		"null", "tdx_guest", "sev-guest", "nvidiactl", "nvidia-uvm",
		"nvidia-uvm-tools", "nvidia-caps", "nvidia-nvswitchctl", "nvidia-nvlink",
	}
	for index := 0; index < 16; index++ {
		want = append(want, fmt.Sprintf("nvidia%d", index), fmt.Sprintf("nvidia-nvswitch%d", index))
	}
	policy := Policies()[hardening.ServiceShim]
	if !reflect.DeepEqual(policy.AttestationDevices, want) {
		t.Fatalf("shim devices = %v, want %v", policy.AttestationDevices, want)
	}
	policy.AttestationDevices[0] = "changed"
	if Policies()[hardening.ServiceShim].AttestationDevices[0] != "null" {
		t.Fatal("policy declarations share mutable device lists")
	}
}

func TestInferencePoliciesPreserveRestrictions(t *testing.T) {
	policies := Policies()
	if len(policies) != 4 {
		t.Fatalf("policies = %#v", policies)
	}
	for _, service := range []hardening.Service{ServiceContainers, ServiceEgress} {
		policy := policies[service]
		if !policy.NoNewPrivileges || !policy.RestrictFilesystems || !policy.RestrictNamespaceOps || len(policy.AttestationDevices) != 0 {
			t.Fatalf("restrictions for %s = %#v", service, policy)
		}
		if !reflect.DeepEqual(policy.BoundCapabilities, []int{unix.CAP_NET_ADMIN}) {
			t.Fatalf("capabilities for %s = %v", service, policy.BoundCapabilities)
		}
		wantDomains := []uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK}
		if service == ServiceContainers {
			wantDomains = append([]uint32{unix.AF_UNIX}, wantDomains...)
		}
		if !reflect.DeepEqual(policy.AllowedSocketDomains, wantDomains) {
			t.Fatalf("socket domains for %s = %v", service, policy.AllowedSocketDomains)
		}
	}
}
