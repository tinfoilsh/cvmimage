package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/pid1/hardening"
	pidruntime "tinfoil/internal/pid1/runtime"
	"tinfoil/internal/pid1/supervisor"
)

type fakeServices struct {
	mu        sync.Mutex
	started   []supervisor.Service
	startedCh chan string
	drained   chan [][]string
	fail      map[string]error
	observe   func(supervisor.State)
}

func newFakeServices() *fakeServices {
	return &fakeServices{
		startedCh: make(chan string, 16),
		drained:   make(chan [][]string, 1),
		fail:      map[string]error{},
	}
}

func (f *fakeServices) Start(_ context.Context, service supervisor.Service) error {
	f.mu.Lock()
	f.started = append(f.started, service)
	err := f.fail[service.Name]
	f.mu.Unlock()
	f.startedCh <- service.Name
	if err != nil {
		f.observe(supervisor.State{Name: service.Name, Required: service.Required, Err: err})
		return err
	}
	f.observe(supervisor.State{Name: service.Name, Required: service.Required, Ready: true})
	return nil
}

func (f *fakeServices) Drain(groups [][]string, _, _ time.Duration) error {
	f.drained <- groups
	return nil
}

func (f *fakeServices) state(name string, ready bool) {
	f.observe(supervisor.State{Name: name, Required: true, Ready: ready})
}

type lifecycleHarness struct {
	services  *fakeServices
	deps      lifecycleDeps
	readiness *readinessState
	ready     chan bool
	existing  map[string]bool
}

func newLifecycleHarness() *lifecycleHarness {
	harness := &lifecycleHarness{
		services: newFakeServices(),
		ready:    make(chan bool, 16),
		existing: map[string]bool{boot.ContainerStatusBinary: true},
	}
	harness.readiness = newReadiness(requiredServiceNames(), func(ready bool) error {
		harness.ready <- ready
		return nil
	})
	harness.services.observe = harness.readiness.Update
	noSetup := func(pidruntime.LogFunc) error { return nil }
	harness.deps = lifecycleDeps{
		services: harness.services,
		oneShot:  func(context.Context, supervisor.Command) error { return nil },
		setupFS:  noSetup,
		sysctls:  noSetup,
		ramdisk:  noSetup,
		limits:   func() error { return nil },
		syslog:   func(context.Context) {},
		exists: func(path string) (bool, error) {
			return harness.existing[path], nil
		},
		timeout: time.Hour,
	}
	return harness
}

func receiveTest[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lifecycle event")
		var zero T
		return zero
	}
}

func TestStartupFailureDrainsStartedServices(t *testing.T) {
	harness := newLifecycleHarness()
	harness.services.fail[dockerName] = errors.New("dockerd start failed")
	result := make(chan error, 1)
	go func() {
		result <- runLifecycle(context.Background(), harness.deps, harness.readiness)
	}()

	if got := receiveTest(t, harness.services.startedCh); got != containerdName {
		t.Fatalf("first service = %s", got)
	}
	if got := receiveTest(t, harness.services.startedCh); got != dockerName {
		t.Fatalf("second service = %s", got)
	}
	groups := receiveTest(t, harness.services.drained)
	if fmt.Sprint(groups) != fmt.Sprint(shutdownGroups()) {
		t.Fatalf("drain groups = %v, want %v", groups, shutdownGroups())
	}
	if err := receiveTest(t, result); err == nil || !errors.Is(err, harness.services.fail[dockerName]) {
		t.Fatalf("runLifecycle error = %v", err)
	}
}

func TestBootDeadlineDoesNotEndSupervisionAndRequiredDeathFailsClosed(t *testing.T) {
	harness := newLifecycleHarness()
	parent, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runLifecycle(parent, harness.deps, harness.readiness)
	}()

	if ready := receiveTest(t, harness.ready); !ready {
		t.Fatal("lifecycle did not become ready")
	}
	// runLifecycle cancels its boot context immediately after publishing
	// readiness. The signal-only parent must remain the sole lifetime gate.
	select {
	case err := <-result:
		t.Fatalf("boot context ended supervision: %v", err)
	default:
	}
	harness.services.state(dockerName, false)
	if ready := receiveTest(t, harness.ready); ready {
		t.Fatal("required service death did not fail closed")
	}
	harness.services.state(dockerName, true)
	if ready := receiveTest(t, harness.ready); !ready {
		t.Fatal("readiness was not restored after required service recovered")
	}
	cancel()
	if err := receiveTest(t, result); err != nil {
		t.Fatalf("clean cancellation returned %v", err)
	}
	if ready := receiveTest(t, harness.ready); ready {
		t.Fatal("shutdown did not clear readiness")
	}
}

func TestHardeningWrapperAppliesPolicyBeforeExec(t *testing.T) {
	var calls []string
	err := execService(
		[]string{string(hardening.ServiceShim), "--", "/usr/bin/tinfoil-shim", "-c", "/config"},
		func(service hardening.Service) error {
			calls = append(calls, "apply:"+string(service))
			return nil
		},
		func(path string, args, env []string) error {
			calls = append(calls, "exec:"+path)
			if got := fmt.Sprint(args); got != "[/usr/bin/tinfoil-shim -c /config]" {
				t.Fatalf("exec args = %s", got)
			}
			if len(env) == 0 {
				t.Fatal("exec environment is empty")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"apply:tinfoil-shim", "exec:/usr/bin/tinfoil-shim"}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("dispatch calls = %v, want %v", calls, want)
	}
}
