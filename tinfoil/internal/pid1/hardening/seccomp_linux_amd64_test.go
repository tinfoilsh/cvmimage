package hardening

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServiceSocketDomains(t *testing.T) {
	if os.Getenv("TINFOIL_SOCKET_DOMAIN_CHILD") == "1" {
		service := Service(os.Getenv("TINFOIL_SOCKET_SERVICE"))
		domain, err := strconv.Atoi(os.Getenv("TINFOIL_SOCKET_DOMAIN"))
		if err != nil {
			os.Exit(20)
		}
		wantAllowed, err := strconv.ParseBool(os.Getenv("TINFOIL_SOCKET_ALLOWED"))
		if err != nil {
			os.Exit(21)
		}
		policy, ok := policyFor(service)
		if !ok || policy.allowedSocketDomains == nil {
			os.Exit(22)
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			os.Exit(23)
		}
		if err := (linuxServiceKernel{}).restrictSyscalls(
			policy.deniedSyscalls,
			policy.restrictNamespaceOps,
			policy.allowedSocketDomains,
		); err != nil {
			os.Exit(24)
		}
		socketType := unix.SOCK_STREAM | unix.SOCK_CLOEXEC
		if domain == unix.AF_NETLINK {
			socketType = unix.SOCK_RAW | unix.SOCK_CLOEXEC
		}
		descriptor, socketErr := unix.Socket(domain, socketType, 0)
		if descriptor >= 0 {
			unix.Close(descriptor)
		}
		if wantAllowed && socketErr != nil {
			os.Exit(25)
		}
		if !wantAllowed && !errors.Is(socketErr, syscall.EAFNOSUPPORT) {
			os.Exit(26)
		}
		os.Exit(0)
	}

	tests := []struct {
		name    string
		service Service
		domain  int
		allowed bool
	}{
		{name: "container-status-unix", service: ServiceContainerStatus, domain: unix.AF_UNIX, allowed: true},
		{name: "container-status-inet", service: ServiceContainerStatus, domain: unix.AF_INET},
		{name: "container-status-packet", service: ServiceContainerStatus, domain: unix.AF_PACKET},
		{name: "container-status-vsock", service: ServiceContainerStatus, domain: unix.AF_VSOCK},
		{name: "shim-inet", service: ServiceShim, domain: unix.AF_INET, allowed: true},
		{name: "shim-inet6", service: ServiceShim, domain: unix.AF_INET6, allowed: true},
		{name: "shim-unix", service: ServiceShim, domain: unix.AF_UNIX},
		{name: "shim-packet", service: ServiceShim, domain: unix.AF_PACKET},
		{name: "shim-vsock", service: ServiceShim, domain: unix.AF_VSOCK},
		{name: "egress-inet", service: ServiceEgress, domain: unix.AF_INET, allowed: true},
		{name: "egress-inet6", service: ServiceEgress, domain: unix.AF_INET6, allowed: true},
		{name: "egress-netlink", service: ServiceEgress, domain: unix.AF_NETLINK, allowed: true},
		{name: "egress-unix", service: ServiceEgress, domain: unix.AF_UNIX},
		{name: "egress-packet", service: ServiceEgress, domain: unix.AF_PACKET},
		{name: "egress-vsock", service: ServiceEgress, domain: unix.AF_VSOCK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestServiceSocketDomains$")
			command.Env = append(os.Environ(),
				"TINFOIL_SOCKET_DOMAIN_CHILD=1",
				"TINFOIL_SOCKET_SERVICE="+string(test.service),
				"TINFOIL_SOCKET_DOMAIN="+strconv.Itoa(test.domain),
				"TINFOIL_SOCKET_ALLOWED="+strconv.FormatBool(test.allowed),
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("socket-domain child failed: %v: %s", err, output)
			}
		})
	}
}

func TestServiceDangerousSyscalls(t *testing.T) {
	if os.Getenv("TINFOIL_DANGEROUS_SYSCALL_CHILD") == "1" {
		service := Service(os.Getenv("TINFOIL_SYSCALL_SERVICE"))
		operation := os.Getenv("TINFOIL_SYSCALL_OPERATION")
		policy, ok := policyFor(service)
		if !ok {
			os.Exit(30)
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			os.Exit(31)
		}
		if err := (linuxServiceKernel{}).restrictSyscalls(
			policy.deniedSyscalls,
			policy.restrictNamespaceOps,
			policy.allowedSocketDomains,
		); err != nil {
			os.Exit(32)
		}

		var errno syscall.Errno
		switch operation {
		case "finit-module":
			_, _, errno = unix.RawSyscall(unix.SYS_FINIT_MODULE, ^uintptr(0), 0, 0)
		case "mount":
			_, _, errno = unix.RawSyscall6(unix.SYS_MOUNT, 0, 0, 0, 0, 0, 0)
		case "io-uring-setup":
			_, _, errno = unix.RawSyscall(unix.SYS_IO_URING_SETUP, 0, 0, 0)
		case "io-uring-enter":
			_, _, errno = unix.RawSyscall6(unix.SYS_IO_URING_ENTER, 0, 0, 0, 0, 0, 0)
		case "io-uring-register":
			_, _, errno = unix.RawSyscall(unix.SYS_IO_URING_REGISTER, 0, 0, 0)
		case "namespace-clone":
			_, _, errno = unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.CLONE_NEWNS), 0, 0, 0, 0, 0)
		case "clone3":
			_, _, errno = unix.RawSyscall6(unix.SYS_CLONE3, 0, 0, 0, 0, 0, 0)
		case "x32":
			_, _, errno = unix.RawSyscall(uintptr(x32SyscallBit|unix.SYS_GETPID), 0, 0, 0)
		default:
			os.Exit(33)
		}

		want := syscall.EPERM
		if operation == "clone3" || operation == "x32" {
			want = syscall.ENOSYS
		}
		if errno != want {
			os.Exit(34)
		}
		os.Exit(0)
	}

	tests := []struct {
		name      string
		service   Service
		operation string
	}{
		{name: "boot-cannot-load-modules", service: ServiceBoot, operation: "finit-module"},
		{name: "boot-cannot-io-uring-setup", service: ServiceBoot, operation: "io-uring-setup"},
		{name: "shim-cannot-io-uring-setup", service: ServiceShim, operation: "io-uring-setup"},
		{name: "egress-cannot-io-uring-enter", service: ServiceEgress, operation: "io-uring-enter"},
		{name: "status-cannot-io-uring-register", service: ServiceContainerStatus, operation: "io-uring-register"},
		{name: "shim-cannot-mount", service: ServiceShim, operation: "mount"},
		{name: "shim-forces-clone3-fallback", service: ServiceShim, operation: "clone3"},
		{name: "egress-cannot-clone-namespace", service: ServiceEgress, operation: "namespace-clone"},
		{name: "status-rejects-x32", service: ServiceContainerStatus, operation: "x32"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestServiceDangerousSyscalls$")
			command.Env = append(os.Environ(),
				"TINFOIL_DANGEROUS_SYSCALL_CHILD=1",
				"TINFOIL_SYSCALL_SERVICE="+string(test.service),
				"TINFOIL_SYSCALL_OPERATION="+test.operation,
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("dangerous-syscall child failed: %v: %s", err, output)
			}
		})
	}
}
