package main

import (
	"testing"

	"tinfoil/internal/pid1/hardening"
)

func TestSandboxCannotSelectInferencePolicies(t *testing.T) {
	spec := lifecycleSpec()
	for _, service := range []hardening.Service{"tinfoil-containers", "tinfoil-egress", "unknown"} {
		if err := spec.ApplyService(service); err == nil {
			t.Fatalf("accepted policy %s", service)
		}
	}
	if _, ok := spec.Environment["DOCKER_HOST"]; ok {
		t.Fatal("sandbox declares a Docker environment")
	}
}
