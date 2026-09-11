package variant

import (
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"tinfoil/internal/pid1/hardening"
)

func TestInferencePoliciesPreserveRestrictions(t *testing.T) {
	policies := Policies()
	if len(policies) != 4 {
		t.Fatalf("policies = %#v", policies)
	}
	for _, service := range []hardening.Service{ServiceContainers, ServiceEgress} {
		policy := policies[service]
		if !policy.NoNewPrivileges || !policy.RestrictFilesystems || !policy.RestrictNamespaceOps || policy.ExposeAttestationDevices {
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
