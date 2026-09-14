package main

import (
	"context"
	"testing"
	"time"
	"tinfoil/internal/pid1/supervisor"
	"tinfoil/pid1"
)

type captureServices struct{ service supervisor.Service }

func (c *captureServices) Start(_ context.Context, service supervisor.Service) error {
	c.service = service
	return nil
}
func (*captureServices) Drain([][]string, time.Duration, time.Duration) error { return nil }

func TestSandboxDoesNotRestartEnrollmentWithinABoot(t *testing.T) {
	services := &captureServices{}
	if err := lifecycleSpec().StartWorkload(context.Background(), pid1.Deps{Services: services}, nil); err != nil {
		t.Fatal(err)
	}
	if services.service.Restart || !services.service.Required {
		t.Fatal("sandbox must fail the boot if enrollment process exits")
	}
	if services.service.Command.Path != "/proc/self/exe" {
		t.Fatal("sandbox bypassed service hardening")
	}
}
