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
)

func (linuxServiceKernel) restrictSocketDomains(domains []uint32) error {
	filters := socketDomainFilters(domains)
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

func socketDomainFilters(domains []uint32) []unix.SockFilter {
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArchOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.AUDIT_ARCH_X86_64},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataNumberOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: uint8(2*len(domains) + 2), K: unix.SYS_SOCKET},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArg0Offset},
	}
	for _, domain := range domains {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: domain},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		)
	}
	return append(filters,
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	)
}
