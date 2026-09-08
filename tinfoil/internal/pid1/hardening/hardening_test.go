package hardening

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServicePoliciesAreExact(t *testing.T) {
	want := map[Service]servicePolicy{
		ServiceBoot: {
			noNewPrivileges:   true,
			boundCapabilities: []int{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN, unix.CAP_MKNOD},
			deniedSyscalls:    kernelManagementSyscalls,
		},
		ServiceContainers: {
			noNewPrivileges:      true,
			boundCapabilities:    []int{unix.CAP_NET_ADMIN},
			restrictFilesystems:  true,
			deniedSyscalls:       restrictedServiceSyscalls,
			restrictNamespaceOps: true,
			allowedSocketDomains: []uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK},
		},
		ServiceEgress: {
			noNewPrivileges:      true,
			boundCapabilities:    []int{unix.CAP_NET_ADMIN},
			restrictFilesystems:  true,
			deniedSyscalls:       restrictedServiceSyscalls,
			restrictNamespaceOps: true,
			allowedSocketDomains: []uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK},
		},
		ServiceShim: {
			noNewPrivileges:          true,
			boundCapabilities:        []int{unix.CAP_NET_BIND_SERVICE},
			restrictFilesystems:      true,
			exposeAttestationDevices: true,
			deniedSyscalls:           restrictedServiceSyscalls,
			restrictNamespaceOps:     true,
			allowedSocketDomains:     []uint32{unix.AF_INET, unix.AF_INET6},
		},
		ServiceVolumes: {
			noNewPrivileges:      true,
			boundCapabilities:    []int{unix.CAP_SYS_ADMIN, unix.CAP_MKNOD, unix.CAP_CHOWN},
			deniedSyscalls:       volumeServiceSyscalls,
			restrictNamespaceOps: true,
			allowedSocketDomains: []uint32{unix.AF_UNIX},
		},
	}
	for service, wantPolicy := range want {
		got, ok := policyFor(service)
		if !ok {
			t.Fatalf("policyFor(%q) did not find policy", service)
		}
		if !reflect.DeepEqual(got, wantPolicy) {
			t.Errorf("policyFor(%q) = %#v, want %#v", service, got, wantPolicy)
		}
	}
	if _, ok := policyFor(Service("unknown")); ok {
		t.Fatal("policyFor accepted unknown service")
	}
}

func TestPackCapabilitiesPacksLowAndHighCapabilities(t *testing.T) {
	data, err := packCapabilities([]int{unix.CAP_NET_BIND_SERVICE, 33, 63})
	if err != nil {
		t.Fatalf("packCapabilities: %v", err)
	}

	low := uint32(1) << uint(unix.CAP_NET_BIND_SERVICE)
	high := uint32(1)<<1 | uint32(1)<<31
	for _, field := range []struct {
		name string
		low  uint32
		high uint32
	}{
		{name: "effective", low: data[0].Effective, high: data[1].Effective},
		{name: "permitted", low: data[0].Permitted, high: data[1].Permitted},
		{name: "inheritable", low: data[0].Inheritable, high: data[1].Inheritable},
	} {
		if field.low != low || field.high != high {
			t.Errorf("%s words = %#x/%#x, want %#x/%#x", field.name, field.low, field.high, low, high)
		}
	}
}

func TestPackCapabilitiesRejectsOutOfRangeValues(t *testing.T) {
	for _, capability := range []int{-1, maxCapability + 1} {
		t.Run(fmt.Sprint(capability), func(t *testing.T) {
			if _, err := packCapabilities([]int{capability}); err == nil {
				t.Fatalf("packCapabilities(%d) succeeded", capability)
			}
		})
	}
}

func TestApplyServiceAppliesFilesystemsCapabilitiesAndSeccompInOrder(t *testing.T) {
	kernel := &fakeServiceKernel{last: 13}
	if err := applyService(kernel, ServiceEgress); err != nil {
		t.Fatalf("applyService: %v", err)
	}

	wantDropped := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13}
	if !reflect.DeepEqual(kernel.dropped, wantDropped) {
		t.Fatalf("dropped capabilities = %v, want %v", kernel.dropped, wantDropped)
	}
	wantData, err := packCapabilities([]int{unix.CAP_NET_ADMIN})
	if err != nil {
		t.Fatal(err)
	}
	if kernel.capabilityData != wantData {
		t.Fatalf("capability data = %#v, want %#v", kernel.capabilityData, wantData)
	}
	if kernel.calls[0] != "restrict-filesystems" {
		t.Fatalf("first call = %q, want restrict-filesystems; all calls: %v", kernel.calls[0], kernel.calls)
	}
	if got := kernel.calls[len(kernel.calls)-1]; got != "restrict-syscalls" {
		t.Fatalf("last call = %q, want restrict-syscalls; all calls: %v", got, kernel.calls)
	}
	if want := []uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK}; !reflect.DeepEqual(kernel.socketDomains, want) {
		t.Fatalf("socket domains = %v, want %v", kernel.socketDomains, want)
	}
	if !reflect.DeepEqual(kernel.deniedSyscalls, restrictedServiceSyscalls) || !kernel.restrictNamespaceOps {
		t.Fatalf("seccomp policy = denied %v namespaces %t", kernel.deniedSyscalls, kernel.restrictNamespaceOps)
	}
}

func TestApplyServiceBootUsesOnlyRequiredCapabilitiesAndKernelDenylist(t *testing.T) {
	kernel := &fakeServiceKernel{last: 63}
	if err := applyService(kernel, ServiceBoot); err != nil {
		t.Fatalf("applyService: %v", err)
	}
	wantData, err := packCapabilities([]int{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN, unix.CAP_MKNOD})
	if err != nil {
		t.Fatal(err)
	}
	if kernel.capabilityData != wantData {
		t.Fatalf("capability data = %#v, want %#v", kernel.capabilityData, wantData)
	}
	if kernel.calls[0] == "restrict-filesystems" {
		t.Fatalf("boot unexpectedly restricted filesystems: %v", kernel.calls)
	}
	if got := kernel.calls[len(kernel.calls)-1]; got != "restrict-syscalls" {
		t.Fatalf("last call = %q, want restrict-syscalls", got)
	}
	if !reflect.DeepEqual(kernel.deniedSyscalls, kernelManagementSyscalls) || kernel.restrictNamespaceOps {
		t.Fatalf("boot seccomp policy = denied %v namespaces %t", kernel.deniedSyscalls, kernel.restrictNamespaceOps)
	}
}

func TestApplyServiceRejectsUnknownPolicyWithoutKernelChanges(t *testing.T) {
	kernel := &fakeServiceKernel{last: 63}
	err := applyService(kernel, Service("containerd"))
	if err == nil || !strings.Contains(err.Error(), "unknown service hardening policy") {
		t.Fatalf("applyService error = %v, want unknown-policy error", err)
	}
	if len(kernel.calls) != 0 {
		t.Fatalf("unknown policy made kernel calls: %v", kernel.calls)
	}
}

func TestApplyServiceStopsAtFirstKernelFailure(t *testing.T) {
	dropErr := errors.New("drop denied")
	failedCapability := 0
	kernel := &fakeServiceKernel{
		last:              unix.CAP_NET_ADMIN,
		dropFailureAt:     &failedCapability,
		dropCapabilityErr: dropErr,
	}
	err := applyService(kernel, ServiceEgress)
	if !errors.Is(err, dropErr) {
		t.Fatalf("applyService error = %v, want %v", err, dropErr)
	}
	want := []string{"restrict-filesystems", "drop:0"}
	if !reflect.DeepEqual(kernel.calls, want) {
		t.Fatalf("calls after failure = %v, want %v", kernel.calls, want)
	}
}

func TestApplyServiceStopsAtSyscallRestrictionFailure(t *testing.T) {
	restrictErr := errors.New("seccomp denied")
	kernel := &fakeServiceKernel{
		last:                unix.CAP_NET_BIND_SERVICE,
		restrictSyscallsErr: restrictErr,
	}
	err := applyService(kernel, ServiceShim)
	if !errors.Is(err, restrictErr) {
		t.Fatalf("applyService error = %v, want %v", err, restrictErr)
	}
	if got := kernel.calls[len(kernel.calls)-1]; got != "restrict-syscalls" {
		t.Fatalf("last call after syscall restriction failure = %q, want restrict-syscalls", got)
	}
}

func TestApplyServiceDoesNotRestrictSyscallsAfterNoNewPrivilegesFailure(t *testing.T) {
	noNewPrivilegesErr := errors.New("prctl denied")
	kernel := &fakeServiceKernel{
		last:               unix.CAP_NET_BIND_SERVICE,
		noNewPrivilegesErr: noNewPrivilegesErr,
	}
	err := applyService(kernel, ServiceShim)
	if !errors.Is(err, noNewPrivilegesErr) {
		t.Fatalf("applyService error = %v, want %v", err, noNewPrivilegesErr)
	}
	if got := kernel.calls[len(kernel.calls)-1]; got != "no-new-privileges" {
		t.Fatalf("last call after no_new_privileges failure = %q, want no-new-privileges", got)
	}
}

func TestApplyServiceDoesNotSetNoNewPrivilegesAfterCapsetFailure(t *testing.T) {
	capsetErr := errors.New("capset denied")
	kernel := &fakeServiceKernel{
		last:          unix.CAP_NET_BIND_SERVICE,
		capabilityErr: capsetErr,
	}
	err := applyService(kernel, ServiceShim)
	if !errors.Is(err, capsetErr) {
		t.Fatalf("applyService error = %v, want %v", err, capsetErr)
	}
	if got := kernel.calls[len(kernel.calls)-1]; got != "set-capabilities" {
		t.Fatalf("last call after capset failure = %q, want set-capabilities", got)
	}
}

func TestRaisedRlimitOnlyRaisesFloors(t *testing.T) {
	tests := []struct {
		name    string
		current unix.Rlimit
		floor   unix.Rlimit
		want    unix.Rlimit
	}{
		{
			name:    "raises soft and hard",
			current: unix.Rlimit{Cur: 1024, Max: 4096},
			floor:   unix.Rlimit{Cur: runtimeNOFILEFloor, Max: runtimeNOFILEFloor},
			want:    unix.Rlimit{Cur: runtimeNOFILEFloor, Max: runtimeNOFILEFloor},
		},
		{
			name:    "preserves higher limits",
			current: unix.Rlimit{Cur: 1048576, Max: unix.RLIM_INFINITY},
			floor:   unix.Rlimit{Cur: runtimeNOFILEFloor, Max: runtimeNOFILEFloor},
			want:    unix.Rlimit{Cur: 1048576, Max: unix.RLIM_INFINITY},
		},
		{
			name:    "raises only soft",
			current: unix.Rlimit{Cur: 1024, Max: unix.RLIM_INFINITY},
			floor:   unix.Rlimit{Cur: runtimeNOFILEFloor, Max: runtimeNOFILEFloor},
			want:    unix.Rlimit{Cur: runtimeNOFILEFloor, Max: unix.RLIM_INFINITY},
		},
		{
			name:    "hard stays at least soft floor",
			current: unix.Rlimit{Cur: 1, Max: 2},
			floor:   unix.Rlimit{Cur: 8, Max: 4},
			want:    unix.Rlimit{Cur: 8, Max: 8},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := raisedRlimit(test.current, test.floor); got != test.want {
				t.Fatalf("raisedRlimit(%#v, %#v) = %#v, want %#v", test.current, test.floor, got, test.want)
			}
		})
	}
}

func TestApplyRuntimeLimitsRaisesAndVerifiesFloors(t *testing.T) {
	kernel := &fakeRlimitKernel{
		limits: map[int]unix.Rlimit{
			unix.RLIMIT_NOFILE:  {Cur: 1024, Max: 4096},
			unix.RLIMIT_MEMLOCK: {Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY},
		},
	}
	if err := applyRuntimeLimits(kernel); err != nil {
		t.Fatalf("applyRuntimeLimits: %v", err)
	}

	wantNOFILE := unix.Rlimit{Cur: runtimeNOFILEFloor, Max: runtimeNOFILEFloor}
	if got := kernel.limits[unix.RLIMIT_NOFILE]; got != wantNOFILE {
		t.Fatalf("NOFILE = %#v, want %#v", got, wantNOFILE)
	}
	wantSets := []rlimitSet{{resource: unix.RLIMIT_NOFILE, limit: wantNOFILE}}
	if !reflect.DeepEqual(kernel.sets, wantSets) {
		t.Fatalf("setrlimit calls = %#v, want %#v", kernel.sets, wantSets)
	}
	if kernel.getCounts[unix.RLIMIT_NOFILE] != 2 || kernel.getCounts[unix.RLIMIT_MEMLOCK] != 2 {
		t.Fatalf("getrlimit counts = %v, want two verification reads per resource", kernel.getCounts)
	}
}

func TestApplyRuntimeLimitsFailsWhenVerificationStaysBelowFloor(t *testing.T) {
	kernel := &fakeRlimitKernel{
		limits: map[int]unix.Rlimit{
			unix.RLIMIT_NOFILE:  {Cur: 1024, Max: 4096},
			unix.RLIMIT_MEMLOCK: {Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY},
		},
		ignoreSets: true,
	}
	err := applyRuntimeLimits(kernel)
	if err == nil || !strings.Contains(err.Error(), "stayed below requested floor") {
		t.Fatalf("applyRuntimeLimits error = %v, want verification error", err)
	}
	if kernel.getCounts[unix.RLIMIT_MEMLOCK] != 0 {
		t.Fatalf("continued to MEMLOCK after NOFILE verification failure: %v", kernel.getCounts)
	}
}

type fakeServiceKernel struct {
	last                   int
	dropFailureAt          *int
	dropCapabilityErr      error
	capabilityErr          error
	noNewPrivilegesErr     error
	restrictFilesystemsErr error
	restrictSyscallsErr    error

	calls                []string
	dropped              []int
	capabilityData       [2]unix.CapUserData
	deniedSyscalls       []uint32
	restrictNamespaceOps bool
	socketDomains        []uint32
}

func (kernel *fakeServiceKernel) restrictFilesystems(exposeAttestation bool) error {
	kernel.calls = append(kernel.calls, "restrict-filesystems")
	if exposeAttestation {
		kernel.calls = append(kernel.calls, "expose-attestation-devices")
	}
	return kernel.restrictFilesystemsErr
}

func (kernel *fakeServiceKernel) dropBoundingCapability(capability int) error {
	if capability > kernel.last {
		return unix.EINVAL
	}
	kernel.calls = append(kernel.calls, fmt.Sprintf("drop:%d", capability))
	kernel.dropped = append(kernel.dropped, capability)
	if kernel.dropFailureAt != nil && capability == *kernel.dropFailureAt {
		return kernel.dropCapabilityErr
	}
	return nil
}

func (kernel *fakeServiceKernel) setCapabilities(data [2]unix.CapUserData) error {
	kernel.calls = append(kernel.calls, "set-capabilities")
	kernel.capabilityData = data
	return kernel.capabilityErr
}

func (kernel *fakeServiceKernel) setNoNewPrivileges() error {
	kernel.calls = append(kernel.calls, "no-new-privileges")
	return kernel.noNewPrivilegesErr
}

func (kernel *fakeServiceKernel) restrictSyscalls(
	denied []uint32,
	restrictNamespaceOps bool,
	domains []uint32,
) error {
	kernel.calls = append(kernel.calls, "restrict-syscalls")
	kernel.deniedSyscalls = append([]uint32(nil), denied...)
	kernel.restrictNamespaceOps = restrictNamespaceOps
	kernel.socketDomains = append([]uint32(nil), domains...)
	return kernel.restrictSyscallsErr
}

type rlimitSet struct {
	resource int
	limit    unix.Rlimit
}

type fakeRlimitKernel struct {
	limits     map[int]unix.Rlimit
	getCounts  map[int]int
	sets       []rlimitSet
	ignoreSets bool
}

func (kernel *fakeRlimitKernel) getRlimit(resource int) (unix.Rlimit, error) {
	if kernel.getCounts == nil {
		kernel.getCounts = make(map[int]int)
	}
	kernel.getCounts[resource]++
	return kernel.limits[resource], nil
}

func (kernel *fakeRlimitKernel) setRlimit(resource int, limit unix.Rlimit) error {
	kernel.sets = append(kernel.sets, rlimitSet{resource: resource, limit: limit})
	if !kernel.ignoreSets {
		kernel.limits[resource] = limit
	}
	return nil
}
