package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"tinfoil/inference/internal/variant"

	"gopkg.in/yaml.v3"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"
	"tinfoil/inference/internal/containernet"
	"tinfoil/inference/internal/gpuattestation"
	"tinfoil/inference/internal/gpumetrics"
	shimconfig "tinfoil/internal/config"
	"tinfoil/shim"
)

func shimSpec() shim.Spec {
	return shim.Spec{
		UpstreamHost:   containernet.ShimUpstreamIP,
		PublishedPorts: func() (map[string]bool, error) { return publishedPorts(variant.RuntimeConfigPath) },
		Observability:  observability,
	}
}

func main() { shim.Main(shimSpec()) }

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

func observability(config *shimconfig.Config, external *shimconfig.ExternalConfig) (shim.Observability, error) {
	log.Printf("Expected %d GPU(s) for attestation", config.ExpectedGPUs)
	return shim.Observability{
		DeviceEvidence:      gpuattestation.Provider(config.ExpectedGPUs),
		EvidenceUnavailable: "GPU attestation evidence unavailable",
		Handlers: map[string]http.Handler{
			"/.well-known/tinfoil-metrics":    gpumetrics.HandleMetrics(external),
			"/.well-known/metrics":            gpumetrics.HandlePrometheusMetrics(&external.Metadata, external.MetricsAPIKey),
			"/.well-known/tinfoil-containers": containersHandler(),
		},
	}, nil
}
