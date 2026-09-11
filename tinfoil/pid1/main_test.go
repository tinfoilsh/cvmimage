package pid1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/kernelcmdline"
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
	onStart   func(string)
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
	if f.onStart != nil {
		f.onStart(service.Name)
	}
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

const (
	daemonName   = "daemon"
	workloadName = "workload"
)

type fakeVariant struct {
	bootstrap func(context.Context) error
}

func (v *fakeVariant) BootstrapDevices(ctx context.Context, _ Deps) error {
	if v.bootstrap == nil {
		return nil
	}
	return v.bootstrap(ctx)
}

func (*fakeVariant) StartDaemons(ctx context.Context, deps Deps) error {
	return deps.Services.Start(ctx, supervisor.Service{
		Name: daemonName, Required: true, Command: Command(daemonName, "/usr/bin/daemon"),
	})
}

func (*fakeVariant) StartWorkload(ctx context.Context, deps Deps, handoff *os.File) error {
	command := Command(workloadName, "/usr/bin/workload", fmt.Sprintf("--debug=%t", deps.Cmdline.Debug))
	return deps.Services.Start(ctx, supervisor.Service{
		Name: workloadName, Required: true, Command: WithSecretHandoff(command, handoff),
	})
}

func (*fakeVariant) RequiredServices() []string {
	return []string{daemonName, workloadName, ShimName}
}

func (*fakeVariant) ShutdownGroups() [][]string {
	return [][]string{{ShimName}, {workloadName}, {daemonName}}
}

type lifecycleHarness struct {
	services  *fakeServices
	variant   *fakeVariant
	deps      Deps
	readiness *readinessState
	ready     chan bool
	existing  map[string]bool
}

type fakeConsole struct{}

func (*fakeConsole) stop(time.Duration, time.Duration) error { return nil }

func newLifecycleHarness() *lifecycleHarness {
	harness := &lifecycleHarness{
		services: newFakeServices(),
		variant:  &fakeVariant{},
		ready:    make(chan bool, 16),
		existing: map[string]bool{},
	}
	harness.readiness = newReadiness(harness.variant.RequiredServices(), func(ready bool) error {
		harness.ready <- ready
		return nil
	})
	harness.services.observe = harness.readiness.Update
	noSetup := func(pidruntime.LogFunc) error { return nil }
	harness.deps = Deps{
		Services: harness.services,
		OneShot:  func(context.Context, supervisor.Command) error { return nil },
		spec: Spec{
			BootstrapDevices: harness.variant.BootstrapDevices, StartDaemons: harness.variant.StartDaemons,
			StartWorkload: harness.variant.StartWorkload, RequiredServices: harness.variant.RequiredServices(),
			ShutdownGroups: harness.variant.ShutdownGroups(), BootStages: testBootStages,
		},
		startConsole: func(context.Context) (consoleControl, error) {
			return &fakeConsole{}, nil
		},
		lockModules:  func() error { return nil },
		debugFailure: func(context.Context, error) {},
		setupFS:      noSetup,
		sysctls:      noSetup,
		ramdisk:      noSetup,
		limits:       func() error { return nil },
		syslog:       func(context.Context) {},
		exists: func(path string) (bool, error) {
			return harness.existing[path], nil
		},
	}
	return harness
}

func TestLifecycleCommandsCarryCapturedKernelPolicy(t *testing.T) {
	harness := newLifecycleHarness()
	harness.deps.Cmdline = kernelcmdline.Values{ConfigHash: "abc", Debug: true}
	var bootCommand supervisor.Command
	harness.deps.OneShot = func(_ context.Context, command supervisor.Command) error {
		if command.Name == string(hardening.ServiceBoot) {
			bootCommand = command
		}
		return nil
	}
	parent, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runLifecycle(parent, harness.deps, harness.readiness) }()
	if ready := receiveTest(t, harness.ready); !ready {
		t.Fatal("lifecycle did not become ready")
	}
	cancel()
	if err := receiveTest(t, result); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(bootCommand.Args); !strings.Contains(got, "--config-hash=abc --debug=true") {
		t.Fatalf("boot args = %s", got)
	}
	if len(bootCommand.ExtraFiles) != 1 {
		t.Fatalf("boot extra files = %d, want 1", len(bootCommand.ExtraFiles))
	}
	var workloadCommand supervisor.Command
	for _, service := range harness.services.started {
		if service.Name == workloadName {
			workloadCommand = service.Command
		}
	}
	if got := fmt.Sprint(workloadCommand.Args); !strings.Contains(got, "--debug=true") {
		t.Fatalf("workload args = %s", got)
	}
	if len(workloadCommand.ExtraFiles) != 1 || workloadCommand.ExtraFiles[0] != bootCommand.ExtraFiles[0] {
		t.Fatal("boot and workload did not receive the same secret handoff")
	}
	if got := fmt.Sprint(workloadCommand.Args); !strings.Contains(got, "--secrets-fd=3") {
		t.Fatalf("workload args = %s", got)
	}
}

func TestLifecycleOrdersLoopbackThenDevicesBeforeDaemons(t *testing.T) {
	harness := newLifecycleHarness()
	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}
	harness.deps.OneShot = func(_ context.Context, command supervisor.Command) error {
		record(command.Name)
		return nil
	}
	harness.deps.setupFS = func(pidruntime.LogFunc) error {
		record("runtime-filesystems")
		return nil
	}
	harness.deps.startConsole = func(context.Context) (consoleControl, error) {
		record("debug-console")
		return &fakeConsole{}, nil
	}
	harness.variant.bootstrap = func(context.Context) error {
		record("devices")
		return nil
	}
	harness.deps.lockModules = func() error {
		record("module-lock")
		return nil
	}
	harness.services.onStart = record
	parent, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runLifecycle(parent, harness.deps, harness.readiness) }()
	if ready := receiveTest(t, harness.ready); !ready {
		t.Fatal("lifecycle did not become ready")
	}
	cancel()
	if err := receiveTest(t, result); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	filesystems := slices.Index(events, "runtime-filesystems")
	console := slices.Index(events, "debug-console")
	loopback := slices.Index(events, "loopback")
	bootstrap := slices.Index(events, "devices")
	lock := slices.Index(events, "module-lock")
	nftables := slices.Index(events, "nftables")
	daemon := slices.Index(events, daemonName)
	workload := slices.Index(events, workloadName)
	shim := slices.Index(events, ShimName)
	boot := slices.Index(events, string(hardening.ServiceBoot))
	if filesystems < 0 || console != filesystems+1 || loopback != console+1 || bootstrap != loopback+1 || lock != bootstrap+1 || nftables != lock+1 || daemon <= nftables || shim <= daemon || boot <= shim || workload <= boot {
		t.Fatalf("startup events = %v", events)
	}
}

func TestModuleLockFailureStopsBootBeforeServices(t *testing.T) {
	harness := newLifecycleHarness()
	lockErr := errors.New("module lock failed")
	var mu sync.Mutex
	var events []string
	harness.deps.OneShot = func(_ context.Context, command supervisor.Command) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, command.Name)
		return nil
	}
	harness.deps.lockModules = func() error { return lockErr }
	err := runLifecycle(context.Background(), harness.deps, harness.readiness)
	if !errors.Is(err, lockErr) {
		t.Fatalf("runLifecycle error = %v, want module lock failure", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if slices.Contains(events, "nftables") {
		t.Fatalf("nftables ran despite module lock failure: %v", events)
	}
	if len(harness.services.started) != 0 {
		t.Fatalf("services started despite module lock failure: %v", harness.services.started)
	}
}

func TestLifecycleFailureParksBeforeServiceDrain(t *testing.T) {
	harness := newLifecycleHarness()
	setupErr := errors.New("sysctl setup failed")
	harness.deps.sysctls = func(pidruntime.LogFunc) error { return setupErr }
	parked := make(chan error, 1)
	release := make(chan struct{})
	harness.deps.debugFailure = func(_ context.Context, err error) {
		parked <- err
		<-release
	}
	result := make(chan error, 1)
	go func() {
		result <- runLifecycle(context.Background(), harness.deps, harness.readiness)
	}()

	if err := receiveTest(t, parked); !errors.Is(err, setupErr) {
		t.Fatalf("parked error = %v, want %v", err, setupErr)
	}
	select {
	case groups := <-harness.services.drained:
		t.Fatalf("services drained before debug failure release: %v", groups)
	default:
	}
	close(release)
	if groups := receiveTest(t, harness.services.drained); fmt.Sprint(groups) != fmt.Sprint(harness.variant.ShutdownGroups()) {
		t.Fatalf("drain groups = %v, want %v", groups, harness.variant.ShutdownGroups())
	}
	if err := receiveTest(t, result); !errors.Is(err, setupErr) {
		t.Fatalf("runLifecycle error = %v, want %v", err, setupErr)
	}
}

func TestFilesystemSetupFailureDoesNotStartConsole(t *testing.T) {
	harness := newLifecycleHarness()
	setupErr := errors.New("filesystem setup failed")
	harness.deps.setupFS = func(pidruntime.LogFunc) error { return setupErr }
	harness.deps.startConsole = func(context.Context) (consoleControl, error) {
		t.Fatal("console started before filesystem setup completed")
		return nil, nil
	}

	err := runLifecycle(context.Background(), harness.deps, harness.readiness)
	if !errors.Is(err, setupErr) {
		t.Fatalf("runLifecycle error = %v, want %v", err, setupErr)
	}
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
	harness.services.fail[daemonName] = errors.New("daemon start failed")
	result := make(chan error, 1)
	go func() {
		result <- runLifecycle(context.Background(), harness.deps, harness.readiness)
	}()

	if got := receiveTest(t, harness.services.startedCh); got != daemonName {
		t.Fatalf("first service = %s", got)
	}
	groups := receiveTest(t, harness.services.drained)
	if fmt.Sprint(groups) != fmt.Sprint(harness.variant.ShutdownGroups()) {
		t.Fatalf("drain groups = %v, want %v", groups, harness.variant.ShutdownGroups())
	}
	if err := receiveTest(t, result); err == nil || !errors.Is(err, harness.services.fail[daemonName]) {
		t.Fatalf("runLifecycle error = %v", err)
	}
}

func TestAnnotateOneShotFailureIncludesFixedBootStage(t *testing.T) {
	failure := errors.New("boot child exited")
	state := &bootstate.State{Stages: make([]bootstate.Stage, len(testBootStages))}
	for index, name := range testBootStages {
		state.Stages[index] = bootstate.Stage{Name: name, Status: bootstate.StatusOK}
		if name == bootstate.StageNetwork {
			state.Stages[index] = bootstate.Stage{
				Name: bootstate.StageNetwork, Status: bootstate.StatusFailed, Detail: "route rejected",
			}
		}
	}

	got := annotateOneShotFailure(string(hardening.ServiceBoot), failure, func() (*bootstate.State, error) {
		return state, nil
	}, testBootStages)
	if !errors.Is(got, failure) {
		t.Fatalf("annotated error = %v, want wrapped failure", got)
	}
	if want := `boot stage "network" failed: "route rejected"`; !strings.Contains(got.Error(), want) {
		t.Fatalf("annotated error = %q, want %q", got, want)
	}
}

func TestAnnotateOneShotFailureFallsBackToChildError(t *testing.T) {
	failure := errors.New("child exited")
	loadFailure := errors.New("state unavailable")
	for _, test := range []struct {
		name        string
		commandName string
		load        func() (*bootstate.State, error)
	}{
		{
			name:        "other command",
			commandName: "nftables",
			load: func() (*bootstate.State, error) {
				t.Fatal("non-boot command loaded boot state")
				return nil, nil
			},
		},
		{
			name:        "missing state",
			commandName: string(hardening.ServiceBoot),
			load: func() (*bootstate.State, error) {
				return nil, loadFailure
			},
		},
		{
			name:        "no failed stage",
			commandName: string(hardening.ServiceBoot),
			load: func() (*bootstate.State, error) {
				return &bootstate.State{Stages: []bootstate.Stage{{Name: bootstate.StageConfig, Status: bootstate.StatusOK}}}, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := annotateOneShotFailure(test.commandName, failure, test.load, testBootStages); got != failure {
				t.Fatalf("annotateOneShotFailure = %v, want original failure", got)
			}
		})
	}
}

func TestRequiredServiceDeathFailsClosedDuringSupervision(t *testing.T) {
	harness := newLifecycleHarness()
	parent, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runLifecycle(parent, harness.deps, harness.readiness)
	}()

	if ready := receiveTest(t, harness.ready); !ready {
		t.Fatal("lifecycle did not become ready")
	}
	select {
	case err := <-result:
		t.Fatalf("lifecycle ended before shutdown: %v", err)
	default:
	}
	harness.services.state(daemonName, false)
	if ready := receiveTest(t, harness.ready); ready {
		t.Fatal("required service death did not fail closed")
	}
	harness.services.state(daemonName, true)
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

func TestReadinessPublicationAllowsTransientRecovery(t *testing.T) {
	var states []bool
	readiness := newReadiness([]string{"first", "second"}, func(ready bool) error {
		states = append(states, ready)
		return nil
	})
	readiness.Update(supervisor.State{Name: "first", Required: true, Ready: true})
	if err := readiness.Publish(); err != nil {
		t.Fatal(err)
	}
	readiness.Update(supervisor.State{Name: "second", Required: true, Ready: true})
	if got := fmt.Sprint(states); got != "[false true]" {
		t.Fatalf("published readiness states = %s, want [false true]", got)
	}
}

func TestFileReadyWaitsForTheServiceLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containers.ready")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- FileReady(path)(ctx)
	}()

	select {
	case err := <-result:
		t.Fatalf("FileReady returned before readiness or cancellation: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("FileReady cancellation error = %v, want context canceled", err)
	}
}

func TestFileReadyReturnsWhenReadinessIsPublished(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containers.ready")
	writeResult := make(chan error, 1)
	go func() {
		time.Sleep(150 * time.Millisecond)
		writeResult <- os.WriteFile(path, nil, 0o600)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := FileReady(path)(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
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

var testBootStages = []string{bootstate.StageConfig, bootstate.StageNetwork, bootstate.StageIdentity, bootstate.StageShim}
