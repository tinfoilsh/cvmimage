package tinfoilconfig

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type PortMapping struct {
	Host      int
	Container int
}

// ParsePorts parses compose-style "<host>:<container>" entries, so no host-IP
// prefix, no ranges, no /udp suffix.
func ParsePorts(ports []string) ([]PortMapping, error) {
	parsed := make([]PortMapping, 0, len(ports))
	for index, spec := range ports {
		host, container, _ := strings.Cut(spec, ":")
		mapping := PortMapping{Host: parsePort(host), Container: parsePort(container)}
		if mapping.Host == 0 || mapping.Container == 0 {
			return nil, fmt.Errorf(`ports[%d] %q must be "<host>:<container>" with ports in 1..65535`, index, spec)
		}
		parsed = append(parsed, mapping)
	}
	return parsed, nil
}

const AdminSSHGuestPort = 22

// AdminSSHMapping identifies the direct admin SSH mapping.
type AdminSSHMapping struct {
	Container     string
	GuestPort     int
	ContainerPort int
}

// AdminSSH resolves direct SSH from inbound port 22 and an admin container's
// 22:22 mapping. It returns nil when no mapping is enabled. Callers must use a
// validated config and suppress this mapping in the debug-toolbox profile.
func AdminSSH(config *Config) (*AdminSSHMapping, error) {
	if !slices.Contains(config.CVMNetwork.InboundPorts, AdminSSHGuestPort) {
		return nil, nil
	}
	for _, container := range config.Containers {
		if !container.CVMAdmin {
			continue
		}
		ports, err := ParsePorts(container.Ports)
		if err != nil {
			return nil, err
		}
		for _, mapping := range ports {
			if mapping.Host != AdminSSHGuestPort {
				continue
			}
			if mapping.Container != AdminSSHGuestPort {
				return nil, fmt.Errorf("direct admin SSH requires 22:22")
			}
			return &AdminSSHMapping{Container: container.Name, GuestPort: mapping.Host, ContainerPort: mapping.Container}, nil
		}
	}
	return nil, nil
}

func parsePort(field string) int {
	port, err := strconv.Atoi(field)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}
