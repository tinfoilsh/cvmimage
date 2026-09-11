package main

import (
	"strconv"

	"tinfoil/internal/attestation"
	"tinfoil/shim"
)

// Everything the sandbox serves binds the CVM's loopback, so this is the whole
// published set: sshd on 22, and what dev servers, desktops and databases bind
// by default.
var sandboxPorts = []int{22, 3000, 3001, 4000, 5000, 5173, 8000, 8001, 8888, 9000, 9222, 3389, 5900, 3306, 5432, 6379}

func shimSpec() shim.Spec {
	return shim.Spec{
		UpstreamHost:   "127.0.0.1",
		PublishedPorts: publishedPorts,
		Observability: shim.Observability{
			DeviceEvidence: attestation.NoDeviceEvidence,
		},
	}
}

func main() { shim.Main(shimSpec()) }

func publishedPorts() (map[string]bool, error) {
	targets := make(map[string]bool, len(sandboxPorts))
	for _, port := range sandboxPorts {
		targets[strconv.Itoa(port)] = true
	}
	return targets, nil
}
