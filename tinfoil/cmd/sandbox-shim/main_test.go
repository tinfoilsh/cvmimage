package main

import "testing"

func TestSandboxRoutesOnlyToItsLoopbackPorts(t *testing.T) {
	spec := shimSpec()
	if host := spec.UpstreamHost("untrusted"); host != "127.0.0.1" {
		t.Fatal(host)
	}
	ports, err := spec.PublishedPorts("unused")
	if err != nil || !ports["22"] || !ports["3000"] || ports["8080"] || ports["443"] {
		t.Fatalf("ports: %v %v", ports, err)
	}
	if _, err := spec.DeviceEvidence([32]byte{}, 1); err == nil {
		t.Fatal("sandbox accepted a GPU expectation")
	}
}
