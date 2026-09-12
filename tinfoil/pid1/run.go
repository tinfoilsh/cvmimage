package pid1

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/kernelcmdline"
	"tinfoil/internal/pid1/hardening"
	pidruntime "tinfoil/internal/pid1/runtime"
	"tinfoil/internal/pid1/supervisor"
	"tinfoil/internal/secretstore"
)

const (
	shimReadyLimit   = 30 * time.Second
	oneShotStopGrace = 2 * time.Second
	serviceTermGrace = 10 * time.Second
	serviceKillGrace = 5 * time.Second

	ShimName       = string(hardening.ServiceShim)
	readyPath      = "/run/tinfoil-pid1.ready"
	selfExecPath   = "/proc/self/exe"
	pid1Env        = "TINFOIL_PID1"
	pid1EnvValue   = "tinfoil-pid1"
	kmsgInfoPrefix = "<6>"
)

var consoleMu sync.Mutex

// Spec declares the workload lifecycle and the policies available to self-exec children.
type Spec struct {
	BootstrapDevices func(context.Context, Runtime) error
	StartDaemons     func(context.Context, Runtime) error
	StartWorkload    func(context.Context, Runtime, *os.File) error
	Services         []Service
	ShutdownGroups   [][]string
	BootStages       []string
	Environment      map[string]string
}

// Run provisions the guest and supervises its services until ctx is canceled.
func Run(ctx context.Context, spec Spec) error {
	if err := spec.validate(); err != nil {
		return err
	}
	if err := setEnvironment(spec.Environment); err != nil {
		return err
	}
	if err := os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"); err != nil {
		return err
	}
	if err := os.Setenv(pid1Env, pid1EnvValue); err != nil {
		return err
	}
	if os.Getpid() != 1 {
		Logf("warning: running with pid %d, expected pid 1", os.Getpid())
	}
	return run(ctx, spec)
}

// ExecService applies the declared policy on the calling thread and replaces
// the self-exec child with its target process.
func ExecService(args []string, spec Spec) error {
	if err := spec.validate(); err != nil {
		return err
	}
	if err := setEnvironment(spec.Environment); err != nil {
		return err
	}
	return execService(args, spec.ApplyService, syscall.Exec)
}

func setEnvironment(environment map[string]string) error {
	for key, value := range environment {
		if key == "PATH" || key == pid1Env {
			return fmt.Errorf("reserved environment key %s", key)
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return nil
}

type consoleControl interface {
	stop(time.Duration, time.Duration) error
}

// Runtime contains the operations and measured inputs used by workload startup.
type Runtime struct {
	Services interface {
		Start(context.Context, supervisor.Service) error
	}
	OneShot func(context.Context, supervisor.Command) error
	Cmdline kernelcmdline.Values
}

type lifecycleDeps struct {
	Runtime
	drain        func([][]string, time.Duration, time.Duration) error
	spec         Spec
	startConsole func(context.Context) (consoleControl, error)
	lockModules  func() error
	debugFailure func(context.Context, error)
	setupFS      func(pidruntime.LogFunc) error
	sysctls      func(pidruntime.LogFunc) error
	ramdisk      func(pidruntime.LogFunc) error
	limits       func() error
	syslog       func(context.Context)
	term         time.Duration
	kill         time.Duration
}

func run(parent context.Context, spec Spec) (result error) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	cmdline, err := kernelcmdline.Read()
	if err != nil {
		return err
	}
	readiness := newReadiness(spec.requiredServices(), setReady)
	manager := supervisor.NewManager(Logf)
	services := supervisor.New(ctx, manager, supervisor.Config{Observe: func(state supervisor.State) {
		readiness.Update(state)
		if service, ok := spec.service(state.Name); ok && service.Fatal && !state.Ready && ctx.Err() == nil {
			cancel(fmt.Errorf("required service %s stopped: %w", state.Name, errors.Join(errors.New("service unavailable"), state.Err)))
		}
	}})
	deps := lifecycleDeps{
		Runtime: Runtime{Services: services,
			OneShot: func(ctx context.Context, command supervisor.Command) error {
				return runOneShot(ctx, manager, command, oneShotStopGrace, spec.BootStages)
			},
			Cmdline: cmdline,
		},
		drain: services.Drain,
		spec:  spec,
		startConsole: func(ctx context.Context) (consoleControl, error) {
			return startDebugConsole(ctx, manager)
		},
		debugFailure: parkDebugFailure,
		lockModules:  hardening.LockKernelModules,
		setupFS:      pidruntime.SetupFilesystems,
		sysctls:      pidruntime.ApplySysctls,
		ramdisk:      pidruntime.SetupRamdisk,
		limits:       hardening.ApplyRuntimeLimits,
		syslog:       startOptionalSyslogSink,
		term:         serviceTermGrace,
		kill:         serviceKillGrace,
	}
	err = runLifecycle(ctx, deps, readiness)
	if parent.Err() == nil && context.Cause(ctx) != nil {
		err = errors.Join(err, context.Cause(ctx))
	}
	return err
}

func runLifecycle(parent context.Context, deps lifecycleDeps, readiness *readinessState) (result error) {
	var console consoleControl
	defer func() {
		if console != nil {
			result = errors.Join(result, console.stop(deps.term, deps.kill))
		}
	}()
	bootCtx := parent
	runtimeCtx, cancelRuntime := context.WithCancel(parent)
	defer func() {
		readiness.FailClosed()
		cancelRuntime()
		drainErr := deps.drain(deps.spec.ShutdownGroups, deps.term, deps.kill)
		if parent.Err() != nil {
			result = drainErr
		} else {
			result = errors.Join(result, drainErr)
		}
	}()
	defer func() {
		if result != nil && console != nil && deps.debugFailure != nil {
			deps.debugFailure(parent, result)
		}
	}()

	Logf("starting CPU lifecycle")
	if err := deps.setupFS(Logf); err != nil {
		return fmt.Errorf("runtime filesystems: %w", err)
	}
	var err error
	console, err = deps.startConsole(parent)
	if err != nil {
		return fmt.Errorf("start debug console: %w", err)
	}
	if err := deps.sysctls(Logf); err != nil {
		return fmt.Errorf("runtime sysctls: %w", err)
	}
	if err := deps.ramdisk(Logf); err != nil {
		return fmt.Errorf("runtime ramdisk: %w", err)
	}
	if err := deps.limits(); err != nil {
		return fmt.Errorf("runtime limits: %w", err)
	}
	secretHandoff, err := secretstore.NewHandoffFile()
	if err != nil {
		return err
	}
	defer secretHandoff.Close()
	storageHandoff, err := secretstore.NewHandoffFile()
	if err != nil {
		return err
	}
	defer storageHandoff.Close()
	if err := deps.OneShot(bootCtx, Command("loopback", "/usr/sbin/ip", "link", "set", "dev", "lo", "up")); err != nil {
		return err
	}
	if deps.spec.BootstrapDevices != nil {
		if err := deps.spec.BootstrapDevices(bootCtx, deps.Runtime); err != nil {
			return err
		}
	}
	if err := deps.lockModules(); err != nil {
		return fmt.Errorf("lock kernel modules: %w", err)
	}
	if err := deps.OneShot(bootCtx, Command("nftables", "/usr/sbin/nft", "-f", "/etc/nftables.conf")); err != nil {
		return err
	}
	deps.syslog(runtimeCtx)

	if deps.spec.StartDaemons != nil {
		if err := deps.spec.StartDaemons(bootCtx, deps.Runtime); err != nil {
			return err
		}
	}
	// The shim intentionally starts in its ephemeral boot-status phase before
	// provisioning, then upgrades in place as boot publishes private artifacts.
	shim, _ := deps.spec.service(ShimName)
	if err := deps.Services.Start(bootCtx, shim.Process()); err != nil {
		return err
	}
	boot, _ := deps.spec.service(string(hardening.ServiceBoot))
	bootCommand := boot.Process().Command
	bootCommand.Args = append(bootCommand.Args,
		"--config-hash="+deps.Cmdline.ConfigHash,
		fmt.Sprintf("--debug=%t", deps.Cmdline.Debug),
	)
	bootCommand = WithSecretHandoff(bootCommand, secretHandoff)
	if _, ok := deps.spec.service(VolumesName); ok {
		descriptor := bootCommand.AddExtraFile(storageHandoff)
		bootCommand.Args = append(bootCommand.Args, fmt.Sprintf("--storage-fd=%d", descriptor))
	}
	if err := deps.OneShot(bootCtx, bootCommand); err != nil {
		return err
	}
	if service, ok := deps.spec.service(VolumesName); ok {
		process := service.Process()
		process.Command = WithSecretHandoff(process.Command, storageHandoff)
		if err := deps.Services.Start(bootCtx, process); err != nil {
			return fmt.Errorf("volume service: %w", err)
		}
	}
	if err := deps.spec.StartWorkload(bootCtx, deps.Runtime, secretHandoff); err != nil {
		return err
	}

	if err := readiness.Publish(); err != nil {
		return fmt.Errorf("publishing readiness: %w", err)
	}
	Logf("boot complete")
	<-parent.Done()
	Logf("shutdown requested")
	return nil
}

func WithSecretHandoff(command supervisor.Command, handoff *os.File) supervisor.Command {
	childFD := command.AddExtraFile(handoff)
	command.Args = append(command.Args, fmt.Sprintf("--secrets-fd=%d", childFD))
	return command
}

func Command(name, path string, args ...string) supervisor.Command {
	return supervisor.Command{Name: name, Path: path, Args: args, Env: childEnv(), Dir: "/"}
}

func HardenedCommand(policy hardening.Service, path string, args ...string) supervisor.Command {
	wrapperArgs := []string{"--exec-service", string(policy), "--", path}
	wrapperArgs = append(wrapperArgs, args...)
	return Command(string(policy), selfExecPath, wrapperArgs...)
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

func runOneShot(ctx context.Context, manager *supervisor.Manager, cmd supervisor.Command, grace time.Duration, stages []string) error {
	process, err := manager.Start(cmd)
	if err != nil {
		return err
	}
	exit, waitErr := process.Wait(ctx)
	if waitErr == nil {
		return errors.Join(
			annotateOneShotFailure(cmd.Name, exit.Err(), bootstate.Load, stages),
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
	loadState func() (*bootstate.State, error),
	stages []string,
) error {
	if failure == nil || commandName != string(hardening.ServiceBoot) {
		return failure
	}
	state, err := loadState()
	if err != nil {
		return failure
	}
	summary, ok := state.FailureSummary(stages)
	if !ok {
		return failure
	}
	return fmt.Errorf("%w; %s", failure, summary)
}

func EndpointReady(network, address string, limit time.Duration) func(context.Context) error {
	return func(parent context.Context) error {
		ctx, cancel := context.WithTimeout(parent, limit)
		defer cancel()
		return waitForReadiness(ctx, func(ctx context.Context) error {
			connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err == nil {
				_ = connection.Close()
			}
			return err
		})
	}
}

func FileReady(path string) func(context.Context) error {
	return func(parent context.Context) error {
		return waitForReadiness(parent, func(context.Context) error {
			_, err := os.Stat(path)
			return err
		})
	}
}

func waitForReadiness(ctx context.Context, probe func(context.Context) error) error {
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

func childEnv() []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "PATH" && key != pid1Env {
			env = append(env, entry)
		}
	}
	return append(env,
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		pid1Env+"="+pid1EnvValue,
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
			Logf("setting readiness: %v", err)
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
		Logf("clearing readiness: %v", err)
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
		Logf("warning: checking %s: %v", path, err)
		return
	}
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		Logf("warning: starting syslog sink: %v", err)
		return
	}
	if err := os.Chmod(path, 0666); err != nil {
		_ = connection.Close()
		Logf("warning: chmod syslog sink: %v", err)
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
					Logf("syslog sink: %v", err)
				}
				return
			}
			if message := sanitizeSyslogMessage(string(buffer[:count])); message != "" {
				Logf("syslog: %s", message)
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

func Logf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	consoleMu.Lock()
	defer consoleMu.Unlock()
	log.Print("tinfoil-pid1: " + message)
	file, err := os.OpenFile("/dev/kmsg", os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		_, _ = fmt.Fprintf(file, kmsgInfoPrefix+"tinfoil-pid1: %s\n", message)
		_ = file.Close()
	}
}
