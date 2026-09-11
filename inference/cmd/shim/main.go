package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"

	"tinfoil/inference/internal/gpuattestation"
	"tinfoil/inference/internal/gpumetrics"
	"tinfoil/internal/containernet"
	"tinfoil/internal/runtimeconfig"
	"tinfoil/shim"
)

func shimSpec() shim.Spec {
	return shim.Spec{
		UpstreamHost:   upstreamHost,
		PublishedPorts: publishedPorts,
		Observability: shim.Observability{
			DeviceEvidence: gpuattestation.CollectDeviceEvidence,
			DeviceMetrics:  gpumetrics.Collect,
			Handlers:       map[string]http.Handler{"/.well-known/tinfoil-containers": containersHandler()},
		},
	}
}

func main() { shim.Main(shimSpec()) }

// upstreamHost returns the fixed shim-net address assigned to the upstream
// container by tinfoil-boot.
func upstreamHost(string) string {
	return containernet.ShimUpstreamIP
}

func publishedPorts(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var runtime runtimeconfig.Config
	if err := yaml.Unmarshal(data, &runtime); err != nil {
		return nil, err
	}
	targets := map[string]bool{}
	for _, container := range runtime.Containers {
		mappings, err := runtimeconfig.ParsePorts(container.Ports)
		if err != nil {
			return nil, fmt.Errorf("container %s: %v", container.Name, err)
		}
		for _, mapping := range mappings {
			port := strconv.Itoa(mapping.Host)
			targets[port] = true
			log.Printf("Tunnel: CONNECT :%s → %s:%s (%s)", port, containernet.PublishedHostIP, port, container.Name)
		}
	}
	return targets, nil
}
