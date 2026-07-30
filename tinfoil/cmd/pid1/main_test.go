package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/kernelcmdline"
	"tinfoil/internal/nvidia"
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
		existing: map[string]bool{},
	}
	harness.readiness = newReadiness(requiredServiceNames(), func(ready bool) error {
		harness.ready <- ready
		return nil
	})
	harness.services.observe = harness.readiness.Update
	noSetup := func(pidruntime.LogFunc) error { return nil }
	harness.deps = lifecycleDeps{
		services:     harness.services,
		oneShot:      func(context.Context, supervisor.Command) error { return nil },
		nvidia:       func(context.Context) error { return nil },
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
	harness.deps.cmdline = kernelcmdline.Values{ConfigHash: "abc", Debug: true}
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
	if got := fmt.Sprint(bootCommand.Args); !strings.Contains(got, "--config-hash=abc --debug=true") {
		t.Fatalf("boot args = %s", got)
	}
	var containersCommand supervisor.Command
	for _, service := range harness.services.started {
		if service.Name == containersName {
			containersCommand = service.Command
		}
	}
	if got := fmt.Sprint(containersCommand.Args); !strings.Contains(got, "--debug=true") {
		t.Fatalf("containers args = %s", got)
	}
}

type fakeNVIDIA struct {
	mu         sync.Mutex
	calls      []string
	fail       map[string]error
	gpuCount   int
	hasSwitch  bool
	fabricMode nvidia.FabricMode
	fabricErr  error
	temporary  string
}

func newFakeNVIDIA(t *testing.T, gpuCount int) *fakeNVIDIA {
	t.Helper()
	return &fakeNVIDIA{
		fail:      map[string]error{},
		gpuCount:  gpuCount,
		temporary: filepath.Join(t.TempDir(), "nvidia.yaml.tmp"),
	}
}

func (f *fakeNVIDIA) call(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	return f.fail[name]
}

func (f *fakeNVIDIA) GPUCount() (int, error) {
	return f.gpuCount, f.call("gpu-count")
}
func (f *fakeNVIDIA) HasNVSwitch() (bool, error) {
	return f.hasSwitch, f.call("has-nvswitch")
}
func (f *fakeNVIDIA) HoldGPUEnableReferences() error {
	return f.call("hold-pci")
}
func (f *fakeNVIDIA) EnableGPURuntimePowerManagement() error {
	return f.call("runtime-pm")
}
func (f *fakeNVIDIA) LoadCoreKernelModules() error { return f.call("load-core") }
func (f *fakeNVIDIA) WaitForCoreDeviceNodes(_ context.Context, expectedGPUs int) error {
	return f.call(fmt.Sprintf("setup-core-devices-%d", expectedGPUs))
}
func (f *fakeNVIDIA) PreparePersistencedRuntime() error { return f.call("prepare-persistenced") }
func (f *fakeNVIDIA) WaitForPersistenced(context.Context) error {
	return f.call("wait-persistenced")
}
func (f *fakeNVIDIA) LoadUVMKernelModules() error { return f.call("load-uvm") }
func (f *fakeNVIDIA) WaitForUVMDeviceNodes(_ context.Context, expectedGPUs int) error {
	return f.call(fmt.Sprintf("setup-uvm-devices-%d", expectedGPUs))
}
func (f *fakeNVIDIA) LoadModesetKernelModules() error {
	return f.call("load-modeset")
}
func (f *fakeNVIDIA) DetectFabricMode() (nvidia.FabricMode, error) {
	if err := f.call("detect-fabric"); err != nil {
		return nvidia.FabricModeNone, err
	}
	return f.fabricMode, f.fabricErr
}
func (f *fakeNVIDIA) PrepareFabricManagerRuntime() error {
	return f.call("prepare-fabric")
}
func (f *fakeNVIDIA) WaitForFabricManager(context.Context) error {
	return f.call("wait-fabric")
}
func (f *fakeNVIDIA) WaitForNVML(_ context.Context, count int) error {
	return f.call(fmt.Sprintf("wait-nvml-%d", count))
}
func (f *fakeNVIDIA) CreateCDITemporary() (string, error) {
	return f.temporary, f.call("create-cdi")
}
func (f *fakeNVIDIA) PublishCDI(path string) error {
	if path != f.temporary {
		return fmt.Errorf("publish path = %s, want %s", path, f.temporary)
	}
	return f.call("publish-cdi")
}

func TestNVIDIABootstrapExactOrderAndCommandContracts(t *testing.T) {
	t.Setenv("FM_CONFIG_FILE", "poisoned")
	t.Setenv("FM_PID_FILE", "poisoned")
	control := newFakeNVIDIA(t, 8)
	control.fabricMode = nvidia.FabricModeFabricManager
	var commands []supervisor.Command
	var persistencedLimit time.Duration
	oneShot := func(ctx context.Context, command supervisor.Command) error {
		control.calls = append(control.calls, "exec:"+command.Name)
		commands = append(commands, command)
		if command.Name == "nvidia-persistenced" {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("nvidia-persistenced context has no deadline")
			}
			persistencedLimit = time.Until(deadline)
		}
		return nil
	}
	var statuses []nvidia.BootstrapStatus
	err := runNVIDIABootstrap(context.Background(), control, oneShot, func(status nvidia.BootstrapStatus) error {
		control.calls = append(control.calls, fmt.Sprintf("status:%d:%d", status.State, status.GPUCount))
		statuses = append(statuses, status)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		"gpu-count", "hold-pci", "runtime-pm", "load-core", "setup-core-devices-8",
		"prepare-persistenced", "exec:nvidia-persistenced", "wait-persistenced",
		"load-uvm", "setup-uvm-devices-8", "load-modeset", "setup-uvm-devices-8",
		"detect-fabric", "prepare-fabric", "exec:nvidia-fabricmanager", "wait-fabric", "wait-nvml-8",
		"create-cdi", "exec:nvidia-ctk-cdi", "publish-cdi",
		fmt.Sprintf("status:%d:8", nvidia.BootstrapStateReady),
	}
	if !slices.Equal(control.calls, wantOrder) {
		t.Fatalf("calls = %v, want %v", control.calls, wantOrder)
	}
	if persistencedLimit > nvidiaChildLimit || persistencedLimit < nvidiaChildLimit-time.Second {
		t.Fatalf("persistenced child limit = %s, want %s", persistencedLimit, nvidiaChildLimit)
	}
	if len(statuses) != 1 || statuses[0] != nvidia.ReadyBootstrapStatus(8) {
		t.Fatalf("statuses = %#v", statuses)
	}
	if len(commands) != 3 {
		t.Fatalf("commands = %d, want 3", len(commands))
	}
	assertCommand(t, commands[0], "nvidia-persistenced", "/usr/bin/nvidia-persistenced",
		[]string{"--user", "nvidia-persistenced", "--uvm-persistence-mode", "--verbose"})
	assertCommand(t, commands[1], "nvidia-fabricmanager", "/usr/bin/nv-fabricmanager",
		[]string{"-c", fabricConfigPath})
	assertCommand(t, commands[2], "nvidia-ctk-cdi", "/usr/bin/nvidia-ctk",
		[]string{"cdi", "generate", "--output=" + control.temporary})
	env := environmentMap(commands[1].Env)
	if _, ok := env["FM_CONFIG_FILE"]; ok {
		t.Fatalf("Fabric Manager inherited FM_CONFIG_FILE: %#v", env)
	}
	if _, ok := env["FM_PID_FILE"]; ok {
		t.Fatalf("Fabric Manager inherited FM_PID_FILE: %#v", env)
	}
}

func TestNVIDIABootstrapWritesExplicitNoGPUStatus(t *testing.T) {
	control := newFakeNVIDIA(t, 0)
	var got nvidia.BootstrapStatus
	err := runNVIDIABootstrap(context.Background(), control, func(context.Context, supervisor.Command) error {
		t.Fatal("no-GPU bootstrap ran a child")
		return nil
	}, func(status nvidia.BootstrapStatus) error {
		got = status
		control.calls = append(control.calls, "status")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != nvidia.NoGPUBootstrapStatus() {
		t.Fatalf("status = %#v", got)
	}
	if !slices.Equal(control.calls, []string{"gpu-count", "has-nvswitch", "status"}) {
		t.Fatalf("calls = %v", control.calls)
	}
}

func TestNVIDIABootstrapRejectsNVSwitchOnlyTopology(t *testing.T) {
	control := newFakeNVIDIA(t, 0)
	control.hasSwitch = true
	var got nvidia.BootstrapStatus
	err := runNVIDIABootstrap(context.Background(), control, func(context.Context, supervisor.Command) error {
		t.Fatal("NVSwitch-only bootstrap ran a child")
		return nil
	}, func(status nvidia.BootstrapStatus) error {
		got = status
		control.calls = append(control.calls, "status")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != nvidia.FailedBootstrapStatus() {
		t.Fatalf("status = %#v", got)
	}
	if !slices.Equal(control.calls, []string{"gpu-count", "has-nvswitch", "status"}) {
		t.Fatalf("calls = %v", control.calls)
	}
}

func TestWaitForNVIDIADeviceNodesRetriesUntilReadyAndHonorsDeadline(t *testing.T) {
	attempts := 0
	err := waitForNVIDIADeviceNodes(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return errors.New("not ready")
		}
		return nil
	}, time.Second, time.Millisecond)
	if err != nil || attempts != 3 {
		t.Fatalf("wait error = %v, attempts = %d", err, attempts)
	}

	err = waitForNVIDIADeviceNodes(context.Background(), func() error {
		return errors.New("still unavailable")
	}, 5*time.Millisecond, time.Millisecond)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v", err)
	}
}

func TestNVIDIABootstrapFailuresPersistAndContinue(t *testing.T) {
	failure := errors.New("boom")
	for _, failedCall := range []string{
		"gpu-count", "hold-pci", "runtime-pm", "load-core", "setup-core-devices-8",
		"prepare-persistenced", "wait-persistenced", "load-uvm", "setup-uvm-devices-8",
		"load-modeset", "detect-fabric", "prepare-fabric", "wait-fabric", "wait-nvml-8",
		"create-cdi", "publish-cdi",
	} {
		t.Run(failedCall, func(t *testing.T) {
			control := newFakeNVIDIA(t, 8)
			if failedCall == "prepare-fabric" || failedCall == "wait-fabric" {
				control.fabricMode = nvidia.FabricModeFabricManager
			}
			control.fail[failedCall] = failure
			var got nvidia.BootstrapStatus
			err := runNVIDIABootstrap(context.Background(), control,
				func(context.Context, supervisor.Command) error { return nil },
				func(status nvidia.BootstrapStatus) error { got = status; return nil },
			)
			if err != nil {
				t.Fatalf("bootstrap did not hand failure to boot: %v", err)
			}
			if got != nvidia.FailedBootstrapStatus() {
				t.Fatalf("status = %#v", got)
			}
		})
	}
}

func TestNVIDIABootstrapChildFailuresPersistAndStatusWriteFailureIsFatal(t *testing.T) {
	childFailure := errors.New("child failed")
	for _, child := range []string{"nvidia-persistenced", "nvidia-fabricmanager", "nvidia-ctk-cdi"} {
		t.Run(child, func(t *testing.T) {
			control := newFakeNVIDIA(t, 8)
			control.fabricMode = nvidia.FabricModeFabricManager
			var got nvidia.BootstrapStatus
			err := runNVIDIABootstrap(context.Background(), control,
				func(_ context.Context, command supervisor.Command) error {
					if command.Name == child {
						return childFailure
					}
					return nil
				},
				func(status nvidia.BootstrapStatus) error { got = status; return nil },
			)
			if err != nil || got != nvidia.FailedBootstrapStatus() {
				t.Fatalf("error = %v, status = %#v", err, got)
			}
		})
	}
	control := newFakeNVIDIA(t, 8)
	control.fail["hold-pci"] = childFailure
	writeFailure := errors.New("disk failed")
	err := runNVIDIABootstrap(context.Background(), control,
		func(context.Context, supervisor.Command) error { return nil },
		func(nvidia.BootstrapStatus) error { return writeFailure },
	)
	if err == nil || !errors.Is(err, writeFailure) {
		t.Fatalf("status persistence error = %v", err)
	}
	for _, gpuCount := range []int{0, 8} {
		control := newFakeNVIDIA(t, gpuCount)
		err := runNVIDIABootstrap(context.Background(), control,
			func(context.Context, supervisor.Command) error { return nil },
			func(nvidia.BootstrapStatus) error { return writeFailure },
		)
		if err == nil || !errors.Is(err, writeFailure) {
			t.Fatalf("GPU count %d status persistence error = %v", gpuCount, err)
		}
	}
}

func TestNVIDIABootstrapRejectsNVL5WithTypedError(t *testing.T) {
	control := newFakeNVIDIA(t, 8)
	control.fabricErr = &nvidia.ErrNVL5RequiresNVLSM{}
	err := runNVIDIABootstrapSteps(context.Background(), control,
		func(context.Context, supervisor.Command) error { return nil }, 8)
	var typed *nvidia.ErrNVL5RequiresNVLSM
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want ErrNVL5RequiresNVLSM", err)
	}
}

func TestNVIDIABootstrapRejectsUnknownFabricMode(t *testing.T) {
	control := newFakeNVIDIA(t, 8)
	control.fabricMode = nvidia.FabricMode(255)
	if err := runNVIDIABootstrapSteps(context.Background(), control,
		func(context.Context, supervisor.Command) error { return nil }, 8); err == nil {
		t.Fatal("unknown fabric mode succeeded")
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
	loopback := slices.Index(events, "loopback")
	bootstrap := slices.Index(events, "nvidia-bootstrap")
	lock := slices.Index(events, "module-lock")
	nftables := slices.Index(events, "nftables")
	containerd := slices.Index(events, containerdName)
	docker := slices.Index(events, dockerName)
	containers := slices.Index(events, containersName)
	shim := slices.Index(events, shimName)
	boot := slices.Index(events, string(hardening.ServiceBoot))
	if loopback < 0 || bootstrap != loopback+1 || lock != bootstrap+1 || nftables != lock+1 || containerd <= nftables || docker <= containerd || shim <= docker || boot <= shim || containers <= boot {
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
	setupErr := errors.New("filesystem setup failed")
	harness.deps.setupFS = func(pidruntime.LogFunc) error { return setupErr }
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
