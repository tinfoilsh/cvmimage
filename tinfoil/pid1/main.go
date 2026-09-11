package pid1

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

	ShimName       = "tinfoil-shim"
	readyPath      = "/run/tinfoil-pid1.ready"
	selfExecPath   = "/proc/self/exe"
	pid1Env        = "TINFOIL_PID1"
	pid1EnvValue   = "tinfoil-pid1"
	kmsgInfoPrefix = "<6>"
)

var consoleMu sync.Mutex

// Spec declares the workload lifecycle and the policies available to self-exec children.
type Spec struct {
	BootstrapDevices func(context.Context, Deps) error
	StartDaemons     func(context.Context, Deps) error
	StartWorkload    func(context.Context, Deps, *os.File) error
	RequiredServices []string
	ShutdownGroups   [][]string
	BootStages       []string
	Environment      map[string]string
	Policies         map[hardening.Service]hardening.Policy
}

func (s Spec) ApplyService(service hardening.Service) error {
	policy, ok := s.Policies[service]
	if !ok {
		return fmt.Errorf("unknown service hardening policy %q", service)
	}
	return hardening.Apply(service, policy)
}

func Main(spec Spec) {
	log.SetFlags(0)
	if spec.StartWorkload == nil || len(spec.RequiredServices) == 0 || len(spec.BootStages) == 0 {
		log.Fatal("incomplete pid1 spec")
	}
	for _, service := range []hardening.Service{hardening.ServiceBoot, hardening.ServiceShim} {
		if _, ok := spec.Policies[service]; !ok {
			log.Fatalf("missing %s policy", service)
		}
	}
	for key, value := range spec.Environment {
		if key == "PATH" || key == pid1Env {
			log.Fatalf("reserved environment key %s", key)
		}
		if err := os.Setenv(key, value); err != nil {
			log.Fatal(err)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "--exec-service" {
		if err := execService(os.Args[2:], spec.ApplyService, syscall.Exec); err != nil {
			fmt.Fprintf(os.Stderr, "tinfoil-pid1: exec-service: %v\n", err)
			os.Exit(127)
		}
		panic("syscall.Exec returned without an error")
	}
	runPID1(spec)
}

func runPID1(spec Spec) {
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	_ = os.Setenv(pid1Env, pid1EnvValue)
	if os.Getpid() != 1 {
		Logf("warning: running with pid %d, expected pid 1", os.Getpid())
	}

	// This signal-notified context owns both startup and supervision. Narrow
	// readiness checks apply their own operation-specific timeouts.
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(parent, spec)
	if err == nil {
		Logf("shutdown complete; powering off")
		if powerErr := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); powerErr != nil {
			Logf("power off failed: %v; parking", powerErr)
		}
	} else {
		Logf("fatal after cleanup: %v; parking", err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

type ServiceControl interface {
	Start(context.Context, supervisor.Service) error
	Drain([][]string, time.Duration, time.Duration) error
}

type consoleControl interface {
	stop(time.Duration, time.Duration) error
}

type Deps struct {
	Services     ServiceControl
	OneShot      func(context.Context, supervisor.Command) error
	Cmdline      kernelcmdline.Values
	spec         Spec
	startConsole func(context.Context) (consoleControl, error)
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
}

func run(parent context.Context, spec Spec) (result error) {
	cmdline, err := kernelcmdline.Read()
	if err != nil {
		return err
	}
	readiness := newReadiness(spec.RequiredServices, setReady)
	manager := supervisor.NewManager(Logf)
	services := supervisor.New(parent, manager, supervisor.Config{Observe: readiness.Update})
	deps := Deps{
		Services: services,
		OneShot: func(ctx context.Context, command supervisor.Command) error {
			return runOneShot(ctx, manager, command, oneShotStopGrace, spec.BootStages)
		},
		Cmdline: cmdline,
		spec:    spec,
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
		exists:       pathExists,
		term:         serviceTermGrace,
		kill:         serviceKillGrace,
	}
	return runLifecycle(parent, deps, readiness)
}

func runLifecycle(parent context.Context, deps Deps, readiness *readinessState) (result error) {
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
		drainErr := deps.Services.Drain(deps.spec.ShutdownGroups, deps.term, deps.kill)
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
	if err := deps.OneShot(bootCtx, Command("loopback", "/usr/sbin/ip", "link", "set", "dev", "lo", "up")); err != nil {
		return err
	}
	if deps.spec.BootstrapDevices != nil {
		if err := deps.spec.BootstrapDevices(bootCtx, deps); err != nil {
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
		if err := deps.spec.StartDaemons(bootCtx, deps); err != nil {
			return err
		}
	}
	// The shim intentionally starts in its ephemeral boot-status phase before
	// provisioning, then upgrades in place as boot publishes private artifacts.
	if err := deps.Services.Start(bootCtx, supervisor.Service{
		Name: ShimName, Required: true, Restart: true,
		Command: HardenedCommand(hardening.ServiceShim, boot.ShimBinary),
		Ready:   EndpointReady("tcp", "127.0.0.1:443", shimReadyLimit),
		PIDFile: boot.ShimPIDPath,
	}); err != nil {
		return err
	}
	bootCommand := HardenedCommand(
		hardening.ServiceBoot, boot.BootBinary,
		"--config-hash="+deps.Cmdline.ConfigHash,
		fmt.Sprintf("--debug=%t", deps.Cmdline.Debug),
	)
	bootCommand = WithSecretHandoff(bootCommand, secretHandoff)
	if err := deps.OneShot(bootCtx, bootCommand); err != nil {
		return err
	}
	if err := deps.spec.StartWorkload(bootCtx, deps, secretHandoff); err != nil {
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
			annotateOneShotFailure(cmd.Name, exit.Err(), boot.Load, stages),
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
