package main

import "testing"

func TestInferenceCannotSelectSandboxPolicy(t *testing.T) {
	spec := lifecycleSpec()
	if err := spec.ApplyService("tinfoil-sandbox"); err == nil {
		t.Fatal("inference accepted the sandbox policy")
	}
	if spec.Environment["DOCKER_HOST"] != "unix:///run/docker.sock" {
		t.Fatal("inference must declare its Docker endpoint")
	}
}
