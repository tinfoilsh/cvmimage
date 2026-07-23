package hardening

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompDataNumberOffset = 0
	seccompDataArchOffset   = 4
	seccompDataArg0Offset   = 16
	x32SyscallBit           = 0x40000000
)

const namespaceCloneFlags = unix.CLONE_NEWCGROUP |
	unix.CLONE_NEWIPC |
	unix.CLONE_NEWNET |
	unix.CLONE_NEWNS |
	unix.CLONE_NEWPID |
	unix.CLONE_NEWTIME |
	unix.CLONE_NEWUSER |
	unix.CLONE_NEWUTS

func (linuxServiceKernel) restrictSyscalls(
	denied []uint32,
	restrictNamespaceOps bool,
	domains []uint32,
) error {
	filters := serviceSeccompFilters(denied, restrictNamespaceOps, domains)
	program := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	if err := unix.Prctl(
		unix.PR_SET_SECCOMP,
		unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&program)),
		0,
		0,
	); err != nil {
		return fmt.Errorf("install seccomp filter: %w", err)
	}
	return nil
}

func serviceSeccompFilters(denied []uint32, restrictNamespaceOps bool, domains []uint32) []unix.SockFilter {
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArchOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.AUDIT_ARCH_X86_64},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataNumberOffset},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: x32SyscallBit},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
	}
	for _, number := range denied {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: number},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		)
	}
	if restrictNamespaceOps {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 3, K: unix.SYS_CLONE},
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArg0Offset},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1, K: namespaceCloneFlags},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataNumberOffset},
		)
	}
	if domains != nil {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: uint8(2*len(domains) + 2), K: unix.SYS_SOCKET},
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArg0Offset},
		)
		for _, domain := range domains {
			filters = append(filters,
				unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: domain},
				unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
			)
		}
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)},
		)
	}
	return append(filters, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
}
