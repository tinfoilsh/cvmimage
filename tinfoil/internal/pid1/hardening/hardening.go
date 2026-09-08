// Package hardening contains the fixed process-hardening policy used by the
// Tinfoil PID 1. A later PID 1 wrapper applies a service policy in its
// self-exec child immediately before replacing that child with the service.
package hardening

import (
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	maxCapability      = len([2]unix.CapUserData{})*32 - 1
	runtimeNOFILEFloor = 524288
)

// Service identifies one of the fixed Tinfoil-owned service policies.
type Service string

const (
	ServiceBoot       Service = "tinfoil-boot"
	ServiceContainers Service = "tinfoil-containers"
	ServiceEgress     Service = "tinfoil-egress"
	ServiceShim       Service = "tinfoil-shim"
	ServiceVolumes    Service = "tinfoil-volume-worker"
)

type servicePolicy struct {
	noNewPrivileges          bool
	boundCapabilities        []int
	restrictFilesystems      bool
	exposeAttestationDevices bool
	deniedSyscalls           []uint32
	restrictNamespaceOps     bool
	allowedSocketDomains     []uint32
}

// kernelManagementSyscalls are denied for every hardened service, including
// the privileged one-shot boot helper. Most are a deliberate second layer over
// controls enforced elsewhere (module loading via kernel.modules_disabled, bpf/
// perf via sysctl, mount/kexec via dropped capabilities): denying them keeps
// each service protected even if another mechanism regresses. Three are the
// sole control at this layer and are load-bearing on their own: the keyring
// syscalls (add_key/request_key/keyctl) and io_uring, which is denied because
// its ring submits file and socket operations the kernel executes without a
// syscall the rest of this filter could inspect.
var kernelManagementSyscalls = []uint32{
	unix.SYS_ACCT,
	unix.SYS_ADD_KEY,
	unix.SYS_BPF,
	unix.SYS_DELETE_MODULE,
	unix.SYS_FINIT_MODULE,
	unix.SYS_INIT_MODULE,
	unix.SYS_IO_URING_ENTER,
	unix.SYS_IO_URING_REGISTER,
	unix.SYS_IO_URING_SETUP,
	unix.SYS_IOPERM,
	unix.SYS_IOPL,
	unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_KEXEC_LOAD,
	unix.SYS_KEYCTL,
	unix.SYS_OPEN_BY_HANDLE_AT,
	unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_PROCESS_VM_READV,
	unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_PTRACE,
	unix.SYS_QUOTACTL,
	unix.SYS_QUOTACTL_FD,
	unix.SYS_REBOOT,
	unix.SYS_REQUEST_KEY,
	unix.SYS_SWAPOFF,
	unix.SYS_SWAPON,
	unix.SYS_USERFAULTFD,
}

var restrictedServiceSyscalls = append([]uint32{
	unix.SYS_CHROOT,
	unix.SYS_CLONE3,
	unix.SYS_FANOTIFY_INIT,
	unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT,
	unix.SYS_FSOPEN,
	unix.SYS_FSPICK,
	unix.SYS_MKNOD,
	unix.SYS_MKNODAT,
	unix.SYS_MOUNT,
	unix.SYS_MOUNT_SETATTR,
	unix.SYS_MOVE_MOUNT,
	unix.SYS_NAME_TO_HANDLE_AT,
	unix.SYS_OPEN_TREE,
	unix.SYS_OPEN_TREE_ATTR,
	unix.SYS_PIVOT_ROOT,
	unix.SYS_SETDOMAINNAME,
	unix.SYS_SETHOSTNAME,
	unix.SYS_SETNS,
	unix.SYS_UMOUNT2,
	unix.SYS_UNSHARE,
}, kernelManagementSyscalls...)

var volumeServiceSyscalls = append([]uint32{
	unix.SYS_CHROOT,
	unix.SYS_CLONE3,
	unix.SYS_FANOTIFY_INIT,
	unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT,
	unix.SYS_FSOPEN,
	unix.SYS_FSPICK,
	unix.SYS_MOUNT_SETATTR,
	unix.SYS_MOVE_MOUNT,
	unix.SYS_NAME_TO_HANDLE_AT,
	unix.SYS_OPEN_TREE,
	unix.SYS_OPEN_TREE_ATTR,
	unix.SYS_PIVOT_ROOT,
	unix.SYS_SETDOMAINNAME,
	unix.SYS_SETHOSTNAME,
	unix.SYS_SETNS,
	unix.SYS_UNSHARE,
}, kernelManagementSyscalls...)

// A non-nil empty boundCapabilities list means that no capabilities are
// permitted. Boot is a one-shot privileged helper: its fixed set covers
// device-mapper/mount operations, nftables, and mapper-node creation.
func policyFor(service Service) (servicePolicy, bool) {
	switch service {
	case ServiceBoot:
		return servicePolicy{
			noNewPrivileges:   true,
			boundCapabilities: []int{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN, unix.CAP_MKNOD},
			deniedSyscalls:    kernelManagementSyscalls,
		}, true
	case ServiceContainers:
		return restrictedServicePolicy(
			[]int{unix.CAP_NET_ADMIN},
			[]uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK},
		), true
	case ServiceEgress:
		return restrictedServicePolicy(
			[]int{unix.CAP_NET_ADMIN},
			[]uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK},
		), true
	case ServiceShim:
		policy := restrictedServicePolicy(
			[]int{unix.CAP_NET_BIND_SERVICE},
			[]uint32{unix.AF_INET, unix.AF_INET6},
		)
		policy.exposeAttestationDevices = true
		return policy, true
	case ServiceVolumes:
		return servicePolicy{
			noNewPrivileges:      true,
			boundCapabilities:    []int{unix.CAP_SYS_ADMIN, unix.CAP_MKNOD, unix.CAP_CHOWN},
			deniedSyscalls:       volumeServiceSyscalls,
			restrictNamespaceOps: true,
			allowedSocketDomains: []uint32{unix.AF_UNIX},
		}, true
	default:
		return servicePolicy{}, false
	}
}

func restrictedServicePolicy(capabilities []int, socketDomains []uint32) servicePolicy {
	return servicePolicy{
		noNewPrivileges:      true,
		boundCapabilities:    capabilities,
		restrictFilesystems:  true,
		deniedSyscalls:       restrictedServiceSyscalls,
		restrictNamespaceOps: true,
		allowedSocketDomains: socketDomains,
	}
}

// ApplyService applies the fixed policy for service to the calling process.
// It rejects unknown services. The caller must terminate the child instead of
// executing the target service if ApplyService returns an error.
func ApplyService(service Service) error {
	return applyService(linuxServiceKernel{}, service)
}

type serviceKernel interface {
	restrictFilesystems(bool) error
	dropBoundingCapability(int) error
	setCapabilities([2]unix.CapUserData) error
	setNoNewPrivileges() error
	restrictSyscalls([]uint32, bool, []uint32) error
}

func applyService(kernel serviceKernel, service Service) error {
	policy, ok := policyFor(service)
	if !ok {
		return fmt.Errorf("unknown service hardening policy %q", service)
	}

	if policy.restrictFilesystems {
		if err := kernel.restrictFilesystems(policy.exposeAttestationDevices); err != nil {
			return fmt.Errorf("restrict filesystems for %s: %w", service, err)
		}
	}

	if policy.boundCapabilities != nil {
		data, err := packCapabilities(policy.boundCapabilities)
		if err != nil {
			return fmt.Errorf("prepare capability set for %s: %w", service, err)
		}

		allowed := [maxCapability + 1]bool{}
		for _, capability := range policy.boundCapabilities {
			allowed[capability] = true
		}
		for capability := 0; capability <= maxCapability; capability++ {
			if allowed[capability] {
				continue
			}
			if err := kernel.dropBoundingCapability(capability); err != nil &&
				!errors.Is(err, unix.EINVAL) {
				return fmt.Errorf("drop capability %d from %s bounding set: %w", capability, service, err)
			}
		}
		if err := kernel.setCapabilities(data); err != nil {
			return fmt.Errorf("set capabilities for %s: %w", service, err)
		}
	}

	if policy.noNewPrivileges {
		if err := kernel.setNoNewPrivileges(); err != nil {
			return fmt.Errorf("set no_new_privileges for %s: %w", service, err)
		}
	}
	if policy.deniedSyscalls != nil || policy.restrictNamespaceOps || policy.allowedSocketDomains != nil {
		if err := kernel.restrictSyscalls(
			policy.deniedSyscalls,
			policy.restrictNamespaceOps,
			policy.allowedSocketDomains,
		); err != nil {
			return fmt.Errorf("restrict syscalls for %s: %w", service, err)
		}
	}
	return nil
}

type linuxServiceKernel struct{}

func (linuxServiceKernel) dropBoundingCapability(capability int) error {
	return unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0)
}

func (linuxServiceKernel) setCapabilities(data [2]unix.CapUserData) error {
	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	return unix.Capset(&header, &data[0])
}

func (linuxServiceKernel) setNoNewPrivileges() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func packCapabilities(capabilities []int) ([2]unix.CapUserData, error) {
	var data [2]unix.CapUserData
	for _, capability := range capabilities {
		if capability < 0 || capability > maxCapability {
			return data, fmt.Errorf("capability %d is outside supported range 0..%d", capability, maxCapability)
		}
		index := capability / 32
		bit := uint32(1) << uint(capability%32)
		data[index].Effective |= bit
		data[index].Permitted |= bit
		data[index].Inheritable |= bit
	}
	return data, nil
}

type runtimeLimit struct {
	name     string
	resource int
	floor    unix.Rlimit
}

var runtimeLimits = []runtimeLimit{
	{
		name:     "nofile",
		resource: unix.RLIMIT_NOFILE,
		floor: unix.Rlimit{
			Cur: runtimeNOFILEFloor,
			Max: runtimeNOFILEFloor,
		},
	},
	{
		name:     "memlock",
		resource: unix.RLIMIT_MEMLOCK,
		floor: unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		},
	},
}

// ApplyRuntimeLimits raises the calling PID 1's NOFILE and MEMLOCK limits to
// their runtime floors without lowering existing limits. It reads each value
// back and fails if the kernel did not apply the requested floor.
func ApplyRuntimeLimits() error {
	return applyRuntimeLimits(linuxRlimitKernel{})
}

type rlimitKernel interface {
	getRlimit(int) (unix.Rlimit, error)
	setRlimit(int, unix.Rlimit) error
}

func applyRuntimeLimits(kernel rlimitKernel) error {
	for _, limit := range runtimeLimits {
		before, err := kernel.getRlimit(limit.resource)
		if err != nil {
			return fmt.Errorf("get rlimit %s: %w", limit.name, err)
		}

		desired := raisedRlimit(before, limit.floor)
		if desired != before {
			if err := kernel.setRlimit(limit.resource, desired); err != nil {
				return fmt.Errorf(
					"set rlimit %s soft=%s hard=%s: %w",
					limit.name,
					formatRlimit(desired.Cur),
					formatRlimit(desired.Max),
					err,
				)
			}
		}

		after, err := kernel.getRlimit(limit.resource)
		if err != nil {
			return fmt.Errorf("verify rlimit %s: %w", limit.name, err)
		}
		hardFloor := max(limit.floor.Cur, limit.floor.Max)
		if after.Cur < limit.floor.Cur || after.Max < hardFloor {
			return fmt.Errorf(
				"rlimit %s stayed below requested floor: soft=%s hard=%s want soft>=%s hard>=%s",
				limit.name,
				formatRlimit(after.Cur),
				formatRlimit(after.Max),
				formatRlimit(limit.floor.Cur),
				formatRlimit(hardFloor),
			)
		}
	}
	return nil
}

func raisedRlimit(current, floor unix.Rlimit) unix.Rlimit {
	desired := current
	hardFloor := max(floor.Cur, floor.Max)
	if desired.Max < hardFloor {
		desired.Max = hardFloor
	}
	if desired.Cur < floor.Cur {
		desired.Cur = floor.Cur
	}
	return desired
}

func formatRlimit(value uint64) string {
	if value == unix.RLIM_INFINITY {
		return "infinity"
	}
	return strconv.FormatUint(value, 10)
}

type linuxRlimitKernel struct{}

func (linuxRlimitKernel) getRlimit(resource int) (unix.Rlimit, error) {
	var limit unix.Rlimit
	err := unix.Getrlimit(resource, &limit)
	return limit, err
}

func (linuxRlimitKernel) setRlimit(resource int, limit unix.Rlimit) error {
	return unix.Setrlimit(resource, &limit)
}
