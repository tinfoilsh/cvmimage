package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	"tinfoil/internal/kernelcmdline"
	"tinfoil/internal/nvidia"
	"tinfoil/internal/pid1/hardening"
	pidruntime "tinfoil/internal/pid1/runtime"
	"tinfoil/internal/pid1/supervisor"
)

const (
	containerdReadyLimit = 30 * time.Second
	dockerReadyLimit     = 60 * time.Second
	containersReadyLimit = 30 * time.Minute
	shimReadyLimit       = 30 * time.Second
	oneShotStopGrace     = 2 * time.Second
	serviceTermGrace     = 10 * time.Second
	serviceKillGrace     = 5 * time.Second
	nvidiaChildLimit     = 4 * time.Minute
	nvidiaDeviceWait     = 15 * time.Second
	nvidiaDevicePoll     = 500 * time.Millisecond
	cdiGenerateLimit     = 30 * time.Second

	containerdName   = "containerd"
	dockerName       = "dockerd"
	containersName   = "tinfoil-containers"
	shimName         = "tinfoil-shim"
	egressName       = "tinfoil-egress"
	containerdSocket = "/run/containerd/containerd.sock"
	dockerSocket     = "/run/docker.sock"
	readyPath        = "/run/tinfoil-pid1.ready"
	selfExecPath     = "/proc/self/exe"
	pid1Env          = "TINFOIL_PID1"
	pid1EnvValue     = "tinfoil-pid1"
	kmsgInfoPrefix   = "<6>"
	fabricConfigPath = "/usr/share/nvidia/nvswitch/fabricmanager.cfg"
)

var consoleMu sync.Mutex

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "--exec-service" {
		if err := execService(os.Args[2:], hardening.ApplyService, syscall.Exec); err != nil {
			fmt.Fprintf(os.Stderr, "tinfoil-pid1: exec-service: %v\n", err)
			os.Exit(127)
		}
		panic("syscall.Exec returned without an error")
	}
	runPID1()
}

func runPID1() {
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	_ = os.Setenv(pid1Env, pid1EnvValue)
	if os.Getpid() != 1 {
		initLogf("warning: running with pid %d, expected pid 1", os.Getpid())
	}

	// This signal-notified context owns both startup and supervision. Narrow
	// readiness checks apply their own operation-specific timeouts.
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(parent)
	if err == nil {
		initLogf("shutdown complete; powering off")
		if powerErr := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); powerErr != nil {
			initLogf("power off failed: %v; parking", powerErr)
		}
	} else {
		initLogf("fatal after cleanup: %v; parking", err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

type serviceControl interface {
	Start(context.Context, supervisor.Service) error
	Drain([][]string, time.Duration, time.Duration) error
}

type lifecycleDeps struct {
	services     serviceControl
	oneShot      func(context.Context, supervisor.Command) error
	nvidia       func(context.Context) error
	lockModules  func() error
	debugFailure func(context.Context, error)
	setupFS      func(pidruntime.LogFunc) error
	sysctls      func(pidruntime.LogFunc) error
	ramdisk      func(pidruntime.LogFunc) error
	limits       func() error
	syslog       func(context.Context)
	exists       func(string) (bool, error)
	term         time.Duration
	kill         time.Duration
	cmdline      kernelcmdline.Values
}

func run(parent context.Context) (result error) {
	cmdline, err := kernelcmdline.Read()
	if err != nil {
		return err
	}
	readiness := newReadiness(requiredServiceNames(), setReady)
	manager := supervisor.NewManager(initLogf)
	console, err := startDebugConsole(parent, manager)
	if err != nil {
		return fmt.Errorf("start debug console: %w", err)
	}
	defer func() {
		result = errors.Join(result, console.stop(serviceTermGrace, serviceKillGrace))
	}()
	services := supervisor.New(parent, manager, supervisor.Config{Observe: readiness.Update})
	deps := lifecycleDeps{
		services: services,
		oneShot: func(ctx context.Context, command supervisor.Command) error {
			return runOneShot(ctx, manager, command, oneShotStopGrace)
		},
		nvidia: func(ctx context.Context) error {
			control := newSystemNVIDIA()
			return runNVIDIABootstrap(
				ctx,
				control,
				func(childCtx context.Context, command supervisor.Command) error {
					return runOneShot(childCtx, manager, command, oneShotStopGrace)
				},
				services.Start,
				func(status nvidia.BootstrapStatus) error {
					return nvidia.WriteBootstrapStatus(boot.NVIDIABootstrapStatusPath, status)
				},
			)
		},
		debugFailure: parkDebugFailure,
		lockModules:  hardening.LockKernelModules,
		setupFS:      pidruntime.SetupFilesystems,
		sysctls:      pidruntime.ApplySysctls,
		ramdisk:      pidruntime.SetupRamdisk,
		limits:       hardening.ApplyRuntimeLimits,
		syslog:       startOptionalSyslogSink,
		exists:       pathExists,
		term:         serviceTermGrace,
		kill:         serviceKillGrace,
		cmdline:      cmdline,
	}
	return runLifecycle(parent, deps, readiness)
}

func runLifecycle(parent context.Context, deps lifecycleDeps, readiness *readinessState) (result error) {
	bootCtx := parent
	runtimeCtx, cancelRuntime := context.WithCancel(parent)
	defer func() {
		readiness.FailClosed()
		cancelRuntime()
		drainErr := deps.services.Drain(shutdownGroups(), deps.term, deps.kill)
		if parent.Err() != nil {
			result = drainErr
		} else {
			result = errors.Join(result, drainErr)
		}
	}()
	defer func() {
		if result != nil && deps.debugFailure != nil {
			deps.debugFailure(parent, result)
		}
	}()

	initLogf("starting CPU lifecycle")
	if err := deps.setupFS(initLogf); err != nil {
		return fmt.Errorf("runtime filesystems: %w", err)
	}
	if err := deps.sysctls(initLogf); err != nil {
		return fmt.Errorf("runtime sysctls: %w", err)
	}
	if err := deps.ramdisk(initLogf); err != nil {
		return fmt.Errorf("runtime ramdisk: %w", err)
	}
	if err := deps.limits(); err != nil {
		return fmt.Errorf("runtime limits: %w", err)
	}
	if err := deps.oneShot(bootCtx, command("loopback", "/usr/sbin/ip", "link", "set", "dev", "lo", "up")); err != nil {
		return err
	}
	if err := deps.nvidia(bootCtx); err != nil {
		return err
	}
	if err := deps.lockModules(); err != nil {
		return fmt.Errorf("lock kernel modules: %w", err)
	}
	if err := deps.oneShot(bootCtx, command("nftables", "/usr/sbin/nft", "-f", "/etc/nftables.conf")); err != nil {
		return err
	}
	deps.syslog(runtimeCtx)

	if err := deps.services.Start(bootCtx, supervisor.Service{
		Name: containerdName, Required: true, Restart: true,
		Command: command(containerdName, "/usr/bin/containerd"),
		Ready:   endpointReady("unix", containerdSocket, containerdReadyLimit),
	}); err != nil {
		return err
	}
	if err := deps.services.Start(bootCtx, supervisor.Service{
		Name: dockerName, Required: true, Restart: true,
		Command: command(dockerName, "/usr/bin/dockerd",
			"-H", "unix://"+dockerSocket, "--containerd="+containerdSocket),
		Ready: endpointReady("unix", dockerSocket, dockerReadyLimit),
	}); err != nil {
		return err
	}
	// The shim intentionally starts in its ephemeral boot-status phase before
	// provisioning, then upgrades in place as boot publishes private artifacts.
	if err := deps.services.Start(bootCtx, supervisor.Service{
		Name: shimName, Required: true, Restart: true,
		Command: hardenedCommand(hardening.ServiceShim, boot.ShimBinary),
		Ready:   endpointReady("tcp", "127.0.0.1:443", shimReadyLimit),
		PIDFile: boot.ShimPIDPath,
	}); err != nil {
		return err
	}
	if err := deps.oneShot(bootCtx, hardenedCommand(
		hardening.ServiceBoot, boot.BootBinary,
		"--config-hash="+deps.cmdline.ConfigHash,
		fmt.Sprintf("--debug=%t", deps.cmdline.Debug),
	)); err != nil {
		return err
	}
	if err := deps.services.Start(bootCtx, supervisor.Service{
		Name: containersName, Required: true, Restart: true,
		Command: hardenedCommand(hardening.ServiceContainers, boot.ContainersBinary,
			fmt.Sprintf("--debug=%t", deps.cmdline.Debug)),
		Ready: fileReady(boot.ContainersReadyPath, containersReadyLimit),
	}); err != nil {
		return err
	}
	if err := deps.services.Start(bootCtx, supervisor.Service{
		Name: egressName, Restart: true,
		Command: hardenedCommand(hardening.ServiceEgress, boot.EgressBinary),
		PIDFile: boot.EgressPIDPath,
	}); err != nil {
		return err
	}

	if err := readiness.Publish(); err != nil {
		return fmt.Errorf("publishing readiness: %w", err)
	}
	initLogf("boot complete")
	<-parent.Done()
	initLogf("shutdown requested")
	return nil
}

type nvidiaBootstrapControl interface {
	GPUCount() (int, error)
	HasNVSwitch() (bool, error)
	HoldGPUEnableReferences() error
	EnableGPURuntimePowerManagement() error
	LoadCoreKernelModules() error
	WaitForCoreDeviceNodes(context.Context, int) error
	PreparePersistencedRuntime() error
	WaitForPersistenced(context.Context) error
	LoadUVMKernelModules() error
	WaitForUVMDeviceNodes(context.Context, int) error
	LoadModesetKernelModules() error
	DetectFabricMode() (nvidia.FabricMode, error)
	PrepareFabricManagerRuntime() error
	WaitForFabricManager(context.Context) error
	WaitForNVML(context.Context, int) error
	CreateCDITemporary() (string, error)
	PublishCDI(string) error
}

type systemNVIDIA struct {
	services *nvidia.Services
}

func newSystemNVIDIA() *systemNVIDIA {
	return &systemNVIDIA{services: nvidia.NewServices()}
}

func (*systemNVIDIA) GPUCount() (int, error)     { return nvidia.GPUCount() }
func (*systemNVIDIA) HasNVSwitch() (bool, error) { return nvidia.HasNVSwitch() }
func (*systemNVIDIA) HoldGPUEnableReferences() error {
	return nvidia.HoldGPUEnableReferences()
}
func (*systemNVIDIA) EnableGPURuntimePowerManagement() error {
	return nvidia.EnableGPURuntimePowerManagement()
}
func (*systemNVIDIA) LoadCoreKernelModules() error { return nvidia.LoadCoreKernelModules() }
func (*systemNVIDIA) WaitForCoreDeviceNodes(ctx context.Context, expectedGPUs int) error {
	return waitForNVIDIADeviceNodes(ctx, func() error {
		return nvidia.SetupCoreDeviceNodes(expectedGPUs)
	}, nvidiaDeviceWait, nvidiaDevicePoll)
}
func (s *systemNVIDIA) PreparePersistencedRuntime() error {
	return s.services.PreparePersistencedRuntime()
}
func (s *systemNVIDIA) WaitForPersistenced(ctx context.Context) error {
	return s.services.WaitForPersistenced(ctx)
}
func (*systemNVIDIA) LoadUVMKernelModules() error { return nvidia.LoadUVMKernelModules() }
func (*systemNVIDIA) WaitForUVMDeviceNodes(ctx context.Context, expectedGPUs int) error {
	return waitForNVIDIADeviceNodes(ctx, func() error {
		return nvidia.SetupUVMDeviceNodes(expectedGPUs)
	}, nvidiaDeviceWait, nvidiaDevicePoll)
}
func (*systemNVIDIA) LoadModesetKernelModules() error {
	return nvidia.LoadModesetKernelModules()
}
func (*systemNVIDIA) DetectFabricMode() (nvidia.FabricMode, error) {
	return nvidia.DetectFabricMode()
}
func (s *systemNVIDIA) PrepareFabricManagerRuntime() error {
	return s.services.PrepareFabricManagerRuntime()
}
func (s *systemNVIDIA) WaitForFabricManager(ctx context.Context) error {
	return s.services.WaitForFabricManager(ctx)
}
func (s *systemNVIDIA) WaitForNVML(ctx context.Context, count int) error {
	return s.services.WaitForNVML(ctx, count)
}
func (s *systemNVIDIA) CreateCDITemporary() (string, error) {
	return s.services.CreateCDITemporary()
}
func (s *systemNVIDIA) PublishCDI(path string) error { return s.services.PublishCDI(path) }

func runNVIDIABootstrap(
	ctx context.Context,
	control nvidiaBootstrapControl,
	oneShot func(context.Context, supervisor.Command) error,
	startService func(context.Context, supervisor.Service) error,
	writeStatus func(nvidia.BootstrapStatus) error,
) error {
	gpuCount, err := control.GPUCount()
	if err == nil && gpuCount == 0 {
		var hasSwitch bool
		hasSwitch, err = control.HasNVSwitch()
		if err == nil && !hasSwitch {
			return writeStatus(nvidia.NoGPUBootstrapStatus())
		}
		if err == nil {
			err = errors.New("NVIDIA NVSwitch topology has no detected GPUs")
		}
	}
	if err == nil {
		err = runNVIDIABootstrapSteps(ctx, control, oneShot, startService, gpuCount)
	}
	if err != nil {
		initLogf("NVIDIA bootstrap failed: %v", err)
		if statusErr := writeStatus(nvidia.FailedBootstrapStatus()); statusErr != nil {
			return fmt.Errorf("persist failed NVIDIA bootstrap status after %v: %w", err, statusErr)
		}
		return nil
	}
	if err := writeStatus(nvidia.ReadyBootstrapStatus(gpuCount)); err != nil {
		return fmt.Errorf("persist ready NVIDIA bootstrap status: %w", err)
	}
	return nil
}

func runNVIDIABootstrapSteps(
	ctx context.Context,
	control nvidiaBootstrapControl,
	oneShot func(context.Context, supervisor.Command) error,
	startService func(context.Context, supervisor.Service) error,
	gpuCount int,
) error {
	if gpuCount < 1 {
		return fmt.Errorf("invalid detected NVIDIA GPU count %d", gpuCount)
	}
	if err := control.HoldGPUEnableReferences(); err != nil {
		return fmt.Errorf("hold NVIDIA PCI enable references: %w", err)
	}
	if err := control.EnableGPURuntimePowerManagement(); err != nil {
		return fmt.Errorf("enable NVIDIA runtime power management: %w", err)
	}
	if err := control.LoadCoreKernelModules(); err != nil {
		return fmt.Errorf("load NVIDIA core kernel modules: %w", err)
	}
	if err := control.WaitForCoreDeviceNodes(ctx, gpuCount); err != nil {
		return fmt.Errorf("set up NVIDIA core device nodes: %w", err)
	}
	if err := control.PreparePersistencedRuntime(); err != nil {
		return fmt.Errorf("prepare nvidia-persistenced runtime: %w", err)
	}
	persistencedCtx, cancelPersistenced := context.WithTimeout(ctx, nvidiaChildLimit)
	err := oneShot(persistencedCtx, command(
		"nvidia-persistenced",
		"/usr/bin/nvidia-persistenced",
		"--user", "nvidia-persistenced", "--uvm-persistence-mode", "--verbose",
	))
	cancelPersistenced()
	if err != nil {
		return fmt.Errorf("start nvidia-persistenced: %w", err)
	}
	if err := control.WaitForPersistenced(ctx); err != nil {
		return fmt.Errorf("wait for nvidia-persistenced: %w", err)
	}
	if err := control.LoadUVMKernelModules(); err != nil {
		return fmt.Errorf("load NVIDIA UVM kernel modules: %w", err)
	}
	if err := control.WaitForUVMDeviceNodes(ctx, gpuCount); err != nil {
		return fmt.Errorf("set up NVIDIA UVM device nodes: %w", err)
	}
	if err := control.LoadModesetKernelModules(); err != nil {
		return fmt.Errorf("load NVIDIA modeset kernel modules: %w", err)
	}
	if err := control.WaitForUVMDeviceNodes(ctx, gpuCount); err != nil {
		return fmt.Errorf("set up NVIDIA modeset device nodes: %w", err)
	}
	fabricMode, err := control.DetectFabricMode()
	if err != nil {
		var nvl5 *nvidia.ErrNVL5RequiresNVLSM
		if errors.As(err, &nvl5) {
			return nvl5
		}
		return fmt.Errorf("detect NVIDIA fabric mode: %w", err)
	}
	switch fabricMode {
	case nvidia.FabricModeNone:
	case nvidia.FabricModeFabricManager:
		if err := control.PrepareFabricManagerRuntime(); err != nil {
			return fmt.Errorf("prepare NVIDIA Fabric Manager runtime: %w", err)
		}
		command := fabricManagerCommand()
		if err := startService(ctx, supervisor.Service{
			Name: command.Name, Restart: true, Command: command,
			Ready: control.WaitForFabricManager,
		}); err != nil {
			return fmt.Errorf("start NVIDIA Fabric Manager: %w", err)
		}
	default:
		return fmt.Errorf("unsupported NVIDIA fabric mode %d", fabricMode)
	}
	if err := control.WaitForNVML(ctx, gpuCount); err != nil {
		return fmt.Errorf("wait for NVIDIA NVML: %w", err)
	}
	temporary, err := control.CreateCDITemporary()
	if err != nil {
		return fmt.Errorf("create NVIDIA CDI temporary file: %w", err)
	}
	defer os.Remove(temporary)
	cdiCtx, cancelCDI := context.WithTimeout(ctx, cdiGenerateLimit)
	defer cancelCDI()
	if err := oneShot(cdiCtx, command(
		"nvidia-ctk-cdi",
		"/usr/bin/nvidia-ctk",
		"cdi", "generate", "--output="+temporary,
	)); err != nil {
		return fmt.Errorf("generate NVIDIA CDI specification: %w", err)
	}
	if err := control.PublishCDI(temporary); err != nil {
		return fmt.Errorf("publish NVIDIA CDI specification: %w", err)
	}
	return nil
}

func waitForNVIDIADeviceNodes(
	ctx context.Context,
	setup func() error,
	limit time.Duration,
	poll time.Duration,
) error {
	waitCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	var lastErr error
	for {
		if err := setup(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		timer := time.NewTimer(poll)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return fmt.Errorf("NVIDIA device readiness failed (%v): %w", lastErr, waitCtx.Err())
		case <-timer.C:
		}
	}
}

func fabricManagerCommand() supervisor.Command {
	cmd := command(
		"nvidia-fabricmanager",
		"/usr/bin/nv-fabricmanager",
		"-c", fabricConfigPath,
	)
	env := make([]string, 0, len(cmd.Env))
	for _, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		if key != "FM_CONFIG_FILE" && key != "FM_PID_FILE" {
			env = append(env, entry)
		}
	}
	cmd.Env = env
	return cmd
}

func requiredServiceNames() []string {
	return []string{containerdName, dockerName, containersName, shimName}
}

func shutdownGroups() [][]string {
	return [][]string{
		{egressName, shimName},
		{containersName},
		{dockerName},
		{containerdName},
	}
}

func command(name, path string, args ...string) supervisor.Command {
	return supervisor.Command{Name: name, Path: path, Args: args, Env: childEnv(), Dir: "/"}
}

func hardenedCommand(policy hardening.Service, path string, args ...string) supervisor.Command {
	wrapperArgs := []string{"--exec-service", string(policy), "--", path}
	wrapperArgs = append(wrapperArgs, args...)
	return command(string(policy), selfExecPath, wrapperArgs...)
}

func execService(
	args []string,
	apply func(hardening.Service) error,
	execFn func(string, []string, []string) error,
) error {
	// Mount namespaces belong to the calling OS thread. Keep this self-exec
	// child pinned from before policy application through the final exec so
	// every later hardening step and the service inherit the restricted view.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if len(args) < 3 || args[1] != "--" {
		return errors.New("usage: --exec-service <policy> -- <path> [args...]")
	}
	policy := hardening.Service(args[0])
	if err := apply(policy); err != nil {
		return fmt.Errorf("apply %s policy: %w", policy, err)
	}
	target := args[2]
	if err := execFn(target, args[2:], childEnv()); err != nil {
		return fmt.Errorf("exec %s: %w", target, err)
	}
	return nil
}

func runOneShot(ctx context.Context, manager *supervisor.Manager, cmd supervisor.Command, grace time.Duration) error {
	process, err := manager.Start(cmd)
	if err != nil {
		return err
	}
	exit, waitErr := process.Wait(ctx)
	if waitErr == nil {
		return errors.Join(
			annotateOneShotFailure(cmd.Name, exit.Err(), boot.Load),
			process.Stop(0, grace),
		)
	}
	cleanupErr := process.Stop(grace, grace)
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), grace)
	_, directWaitErr := process.Wait(cleanupCtx)
	cancelCleanup()
	return fmt.Errorf("%s interrupted: %w", cmd.Name, errors.Join(waitErr, cleanupErr, directWaitErr))
}

func annotateOneShotFailure(
	commandName string,
	failure error,
	loadState func() (*boot.State, error),
) error {
	if failure == nil || commandName != string(hardening.ServiceBoot) {
		return failure
	}
	state, err := loadState()
	if err != nil {
		return failure
	}
	summary, ok := state.FailureSummary()
	if !ok {
		return failure
	}
	return fmt.Errorf("%w; %s", failure, summary)
}

func endpointReady(network, address string, limit time.Duration) func(context.Context) error {
	return func(parent context.Context) error {
		return waitForEndpoint(parent, limit, func(ctx context.Context) error {
			connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err == nil {
				_ = connection.Close()
			}
			return err
		})
	}
}

func fileReady(path string, limit time.Duration) func(context.Context) error {
	return func(parent context.Context) error {
		return waitForEndpoint(parent, limit, func(context.Context) error {
			_, err := os.Stat(path)
			return err
		})
	}
}

func waitForEndpoint(parent context.Context, limit time.Duration, probe func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		probeCtx, probeCancel := context.WithTimeout(ctx, time.Second)
		lastErr = probe(probeCtx)
		probeCancel()
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last probe: %v)", ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
}

func childEnv() []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "PATH" && key != pid1Env && key != "DOCKER_HOST" {
			env = append(env, entry)
		}
	}
	return append(env,
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		pid1Env+"="+pid1EnvValue,
		"DOCKER_HOST=unix://"+dockerSocket,
	)
}

type readinessState struct {
	mu        sync.Mutex
	required  map[string]bool
	published bool
	failed    bool
	set       func(bool) error
}

func newReadiness(required []string, set func(bool) error) *readinessState {
	state := &readinessState{required: map[string]bool{}, set: set}
	for _, name := range required {
		state.required[name] = false
	}
	return state
}

func (r *readinessState) Update(state supervisor.State) {
	if !state.Required {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, expected := r.required[state.Name]; !expected || r.failed {
		return
	}
	r.required[state.Name] = state.Ready
	if r.published {
		if err := r.set(r.allReadyLocked()); err != nil {
			initLogf("setting readiness: %v", err)
		}
	}
}

func (r *readinessState) Publish() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.published = true
	if err := r.set(!r.failed && r.allReadyLocked()); err != nil {
		return err
	}
	return nil
}

func (r *readinessState) FailClosed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	if err := r.set(false); err != nil {
		initLogf("clearing readiness: %v", err)
	}
}

func (r *readinessState) allReadyLocked() bool {
	for _, ready := range r.required {
		if !ready {
			return false
		}
	}
	return true
}

func setReady(ready bool) error {
	if !ready {
		if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return os.WriteFile(readyPath, []byte("ready\n"), 0644)
}

func startOptionalSyslogSink(ctx context.Context) {
	const path = "/dev/log"
	if _, err := os.Lstat(path); err == nil {
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		initLogf("warning: checking %s: %v", path, err)
		return
	}
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		initLogf("warning: starting syslog sink: %v", err)
		return
	}
	if err := os.Chmod(path, 0666); err != nil {
		_ = connection.Close()
		initLogf("warning: chmod syslog sink: %v", err)
		return
	}
	go func() {
		<-ctx.Done()
		_ = connection.Close()
	}()
	go func() {
		defer os.Remove(path)
		buffer := make([]byte, 8192)
		for {
			count, _, err := connection.ReadFromUnix(buffer)
			if err != nil {
				if ctx.Err() == nil {
					initLogf("syslog sink: %v", err)
				}
				return
			}
			if message := sanitizeSyslogMessage(string(buffer[:count])); message != "" {
				initLogf("syslog: %s", message)
			}
		}
	}()
}

func sanitizeSyslogMessage(message string) string {
	message = strings.Trim(message, "\x00\r\n\t ")
	message = strings.ReplaceAll(message, "\n", `\n`)
	message = strings.ReplaceAll(message, "\r", `\r`)
	if len(message) > 512 {
		message = message[:512] + "...<truncated>"
	}
	return message
}

func initLogf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	consoleMu.Lock()
	defer consoleMu.Unlock()
	log.Print("tinfoil-pid1: " + message)
	for _, path := range []string{"/dev/kmsg", "/dev/ttyS0", "/dev/console"} {
		file, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			continue
		}
		if path == "/dev/kmsg" {
			_, _ = fmt.Fprintf(file, kmsgInfoPrefix+"tinfoil-pid1: %s\n", message)
		} else {
			_, _ = fmt.Fprintf(file, "tinfoil-pid1: %s\n", message)
		}
		_ = file.Close()
	}
}
