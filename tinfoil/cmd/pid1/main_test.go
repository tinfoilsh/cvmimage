package main

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

	"tinfoil/internal/boot"
	"tinfoil/internal/kernelcmdline"
	"tinfoil/internal/pid1/hardening"
	pidruntime "tinfoil/internal/pid1/runtime"
	"tinfoil/internal/pid1/supervisor"
	"tinfoil/internal/runtimeconfig"
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

type lifecycleHarness struct {
	services  *fakeServices
	deps      lifecycleDeps
	readiness *readinessState
	ready     chan bool
	existing  map[string]bool
	config    runtimeconfig.Config
}

type fakeConsole struct{}

func (*fakeConsole) stop(time.Duration, time.Duration) error { return nil }

func newLifecycleHarness() *lifecycleHarness {
	harness := &lifecycleHarness{
		services: newFakeServices(),
		ready:    make(chan bool, 16),
		existing: map[string]bool{},
	}
	harness.readiness = newReadiness(requiredServiceNames(), func(ready bool) error {
		harness.ready <- ready
		return nil
	})
	harness.services.observe = harness.readiness.Update
	noSetup := func(pidruntime.LogFunc) error { return nil }
	harness.deps = lifecycleDeps{
		services: harness.services,
		startConsole: func(context.Context) (consoleControl, error) {
			return &fakeConsole{}, nil
		},
		oneShot:          func(context.Context, supervisor.Command) error { return nil },
		nvidia:           func(context.Context) error { return nil },
		lockModules:      func() error { return nil },
		debugFailure:     func(context.Context, error) {},
		setupFS:          noSetup,
		sysctls:          noSetup,
		ramdisk:          noSetup,
		localAttestation: func() (*os.File, error) { return os.Open(os.DevNull) },
		limits:           func() error { return nil },
		syslog:           func(context.Context) {},
		exists: func(path string) (bool, error) {
			return harness.existing[path], nil
		},
		measuredConfig: func() (*runtimeconfig.Config, error) {
			return &harness.config, nil
		},
	}
	return harness
}

func TestLifecycleCommandsCarryCapturedKernelPolicy(t *testing.T) {
	harness := newLifecycleHarness()
	harness.deps.cmdline = kernelcmdline.Values{Debug: true}
	var bootCommand supervisor.Command
	harness.deps.oneShot = func(_ context.Context, command supervisor.Command) error {
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
	if got := fmt.Sprint(bootCommand.Args); !strings.Contains(got, "--debug=true") {
		t.Fatalf("boot args = %s", got)
	}
	if len(bootCommand.ExtraFiles) != 1 {
		t.Fatalf("boot extra files = %d, want 1", len(bootCommand.ExtraFiles))
	}
	var containersCommand, shimCommand supervisor.Command
	for _, service := range harness.services.started {
		if service.Name == containersName {
			containersCommand = service.Command
		}
		if service.Name == shimName {
			shimCommand = service.Command
		}
	}
	if len(shimCommand.ExtraFiles) != 1 || shimCommand.ExtraFiles[0] == nil || shimCommand.ExtraFiles[0] == bootCommand.ExtraFiles[0] {
		t.Fatal("shim did not receive its local attestation listener")
	}
	if !slices.Contains(shimCommand.Args, "--attestation-fd=3") {
		t.Fatalf("shim args = %v", shimCommand.Args)
	}
	if got := fmt.Sprint(containersCommand.Args); !strings.Contains(got, "--debug=true") {
		t.Fatalf("containers args = %s", got)
	}
	if len(containersCommand.ExtraFiles) != 1 || containersCommand.ExtraFiles[0] != bootCommand.ExtraFiles[0] {
		t.Fatal("boot and containers did not receive the same secret handoff")
	}
	if got := fmt.Sprint(containersCommand.Args); !strings.Contains(got, "--secrets-fd=3") {
		t.Fatalf("containers args = %s", got)
	}
}

func TestLifecycleOrdersLoopbackThenNVIDIABeforeContainerd(t *testing.T) {
	harness := newLifecycleHarness()
	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}
	harness.deps.oneShot = func(_ context.Context, command supervisor.Command) error {
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
	harness.deps.nvidia = func(context.Context) error {
		record("nvidia-bootstrap")
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
	bootstrap := slices.Index(events, "nvidia-bootstrap")
	lock := slices.Index(events, "module-lock")
	nftables := slices.Index(events, "nftables")
	containerd := slices.Index(events, containerdName)
	docker := slices.Index(events, dockerName)
	containers := slices.Index(events, containersName)
	shim := slices.Index(events, shimName)
	boot := slices.Index(events, string(hardening.ServiceBoot))
	if filesystems < 0 || console != filesystems+1 || loopback != console+1 || bootstrap != loopback+1 || lock != bootstrap+1 || nftables != lock+1 || containerd <= nftables || docker <= containerd || shim <= docker || boot <= shim || containers <= boot {
		t.Fatalf("startup events = %v", events)
	}
}

func TestModuleLockFailureStopsBootBeforeServices(t *testing.T) {
	harness := newLifecycleHarness()
	lockErr := errors.New("module lock failed")
	var mu sync.Mutex
	var events []string
	harness.deps.oneShot = func(_ context.Context, command supervisor.Command) error {
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
	if groups := receiveTest(t, harness.services.drained); fmt.Sprint(groups) != fmt.Sprint(shutdownGroups()) {
		t.Fatalf("drain groups = %v, want %v", groups, shutdownGroups())
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

func assertCommand(t *testing.T, got supervisor.Command, name, path string, args []string) {
	t.Helper()
	if got.Name != name || got.Path != path || !slices.Equal(got.Args, args) || got.Dir != "/" {
		t.Fatalf("command = %#v, want name=%q path=%q args=%v dir=/", got, name, path, args)
	}
}

func environmentMap(entries []string) map[string]string {
	env := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	return env
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

func TestAnnotateOneShotFailureIncludesFixedBootStage(t *testing.T) {
	failure := errors.New("boot child exited")
	state := &boot.State{Stages: make([]boot.Stage, len(boot.InitialStages))}
	for index, name := range boot.InitialStages {
		state.Stages[index] = boot.Stage{Name: name, Status: boot.StatusOK}
		if name == boot.StageNetwork {
			state.Stages[index] = boot.Stage{
				Name: boot.StageNetwork, Status: boot.StatusFailed, Detail: "route rejected",
			}
		}
	}

	got := annotateOneShotFailure(string(hardening.ServiceBoot), failure, func() (*boot.State, error) {
		return state, nil
	})
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
		load        func() (*boot.State, error)
	}{
		{
			name:        "other command",
			commandName: "nftables",
			load: func() (*boot.State, error) {
				t.Fatal("non-boot command loaded boot state")
				return nil, nil
			},
		},
		{
			name:        "missing state",
			commandName: string(hardening.ServiceBoot),
			load: func() (*boot.State, error) {
				return nil, loadFailure
			},
		},
		{
			name:        "no failed stage",
			commandName: string(hardening.ServiceBoot),
			load: func() (*boot.State, error) {
				return &boot.State{Stages: []boot.Stage{{Name: boot.StageConfig, Status: boot.StatusOK}}}, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := annotateOneShotFailure(test.commandName, failure, test.load); got != failure {
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
		result <- fileReady(path)(ctx)
	}()

	select {
	case err := <-result:
		t.Fatalf("fileReady returned before readiness or cancellation: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("fileReady cancellation error = %v, want context canceled", err)
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
	if err := fileReady(path)(ctx); err != nil {
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

func TestVolumeWorkersStartOnlyForRuntimeUnlocks(t *testing.T) {
	harness := newLifecycleHarness()
	harness.deps.oneShot = func(context.Context, supervisor.Command) error {
		t.Fatal("PID 1 attempted to mount a volume already handled by boot")
		return nil
	}
	harness.config = runtimeconfig.Config{
		Models: []runtimeconfig.ModelSpec{{Name: "one"}, {Name: "two"}},
		Volumes: []runtimeconfig.VolumeSpec{
			{Name: "boot-state", KeySecret: "STATE_KEY"},
			{Name: "state"},
			{Name: "boot-workspace", KeySecret: "WORKSPACE_KEY"},
			{Name: "workspace", Exec: true, Owner: "1000"},
		},
	}
	if err := startVolumeWorkers(context.Background(), harness.deps, &harness.config); err != nil {
		t.Fatal(err)
	}
	started := harness.services.started
	if len(started) != 2 {
		t.Fatalf("started %d services, want 2", len(started))
	}
	want := [][]string{
		{"tinfoil-volume-state", "--models=2", "--index=1", "--name=state", "--exec=false", "--owner="},
		{"tinfoil-volume-workspace", "--models=2", "--index=3", "--name=workspace", "--exec=true", "--owner=1000"},
	}
	for index, service := range started {
		if service.Name != want[index][0] || service.Command.Name != want[index][0] {
			t.Fatalf("service %d named %q/%q, want %q", index, service.Name, service.Command.Name, want[index][0])
		}
		if service.Restart || service.Required {
			t.Fatalf("service %d is supervised as restart=%t required=%t", index, service.Restart, service.Required)
		}
		if service.Ready == nil {
			t.Fatalf("service %d has no readiness probe", index)
		}
		args := []string{"--exec-service", string(hardening.ServiceVolumes), "--", boot.VolumeWorkerBinary}
		args = append(args, want[index][1:]...)
		if fmt.Sprint(service.Command.Args) != fmt.Sprint(args) {
			t.Fatalf("service %d args = %v, want %v", index, service.Command.Args, args)
		}
	}
}
