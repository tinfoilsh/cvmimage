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
		if err := (linuxServiceKernel{}).restrictSocketDomains(policy.allowedSocketDomains); err != nil {
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
