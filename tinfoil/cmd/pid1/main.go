package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
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
	"tinfoil/internal/runtimeconfig"
	"tinfoil/internal/secretstore"
)

const (
	containerdReadyLimit = 30 * time.Second
	dockerReadyLimit     = 60 * time.Second
	shimReadyLimit       = 30 * time.Second
	oneShotStopGrace     = 2 * time.Second
	serviceTermGrace     = 10 * time.Second
	serviceKillGrace     = 5 * time.Second

	containerdName   = "containerd"
	dockerName       = "dockerd"
	containersName   = "tinfoil-containers"
	shimName         = "tinfoil-shim"
	egressName       = "tinfoil-egress"
	volumesName      = "tinfoil-volume"
	containerdSocket = "/run/containerd/containerd.sock"
	dockerSocket     = "/run/docker.sock"
	readyPath        = "/run/tinfoil-pid1.ready"
	selfExecPath     = "/proc/self/exe"
	pid1Env          = "TINFOIL_PID1"
	pid1EnvValue     = "tinfoil-pid1"
	kmsgInfoPrefix   = "<6>"
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

type consoleControl interface {
	stop(time.Duration, time.Duration) error
}

type lifecycleDeps struct {
	services         serviceControl
	startConsole     func(context.Context) (consoleControl, error)
	oneShot          func(context.Context, supervisor.Command) error
	nvidia           func(context.Context) error
	lockModules      func() error
	debugFailure     func(context.Context, error)
	setupFS          func(pidruntime.LogFunc) error
	sysctls          func(pidruntime.LogFunc) error
	ramdisk          func(pidruntime.LogFunc) error
	localAttestation func() (*os.File, error)
	limits           func() error
	syslog           func(context.Context)
	exists           func(string) (bool, error)
	measuredConfig   func() (*runtimeconfig.Config, error)
	term             time.Duration
	kill             time.Duration
	cmdline          kernelcmdline.Values
}

func run(parent context.Context) (result error) {
	cmdline, err := kernelcmdline.Read()
	if err != nil {
		return err
	}
	readiness := newReadiness(requiredServiceNames(), setReady)
	manager := supervisor.NewManager(initLogf)
	services := supervisor.New(parent, manager, supervisor.Config{Observe: readiness.Update})
	deps := lifecycleDeps{
		services: services,
		startConsole: func(ctx context.Context) (consoleControl, error) {
			return startDebugConsole(ctx, manager)
		},
		oneShot: func(ctx context.Context, command supervisor.Command) error {
			return runOneShot(ctx, manager, command, oneShotStopGrace)
		},
		nvidia:       func(ctx context.Context) error { return initializeGPU(ctx, manager, services) },
		debugFailure: parkDebugFailure,
		measuredConfig: func() (*runtimeconfig.Config, error) {
			return readMeasuredConfig(cmdline.Debug)
		},
		lockModules:      hardening.LockKernelModules,
		setupFS:          pidruntime.SetupFilesystems,
		sysctls:          pidruntime.ApplySysctls,
		ramdisk:          pidruntime.SetupRamdisk,
		localAttestation: func() (*os.File, error) { return newLocalAttestationSocket(boot.AttestationSocket) },
		limits:           hardening.ApplyRuntimeLimits,
		syslog:           startOptionalSyslogSink,
		exists:           pathExists,
		term:             serviceTermGrace,
		kill:             serviceKillGrace,
		cmdline:          cmdline,
	}
	return runLifecycle(parent, deps, readiness)
}

func runLifecycle(parent context.Context, deps lifecycleDeps, readiness *readinessState) (result error) {
	var console consoleControl
	var localAttestationSocket *os.File
	defer func() {
		if localAttestationSocket != nil {
			localAttestationSocket.Close()
		}
		if console != nil {
			result = errors.Join(result, console.stop(deps.term, deps.kill))
		}
	}()
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
		if result != nil && console != nil && deps.debugFailure != nil {
			deps.debugFailure(parent, result)
		}
	}()

	initLogf("starting CPU lifecycle")
	if err := deps.setupFS(initLogf); err != nil {
		return fmt.Errorf("runtime filesystems: %w", err)
	}
	var err error
	console, err = deps.startConsole(parent)
	if err != nil {
		return fmt.Errorf("start debug console: %w", err)
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
	secretHandoff, err := secretstore.NewHandoffFile()
	if err != nil {
		return err
	}
	defer secretHandoff.Close()
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
	localAttestationSocket, err = deps.localAttestation()
	if err != nil {
		return fmt.Errorf("local attestation socket: %w", err)
	}
	shimCommand := hardenedCommand(hardening.ServiceShim, boot.ShimBinary)
	shimFD := shimCommand.AddExtraFile(localAttestationSocket)
	shimCommand.Args = append(shimCommand.Args, fmt.Sprintf("--attestation-fd=%d", shimFD))
	if err := deps.services.Start(bootCtx, supervisor.Service{
		Name: shimName, Required: true, Restart: true,
		DrainUntilExit: true,
		Command:        shimCommand,
		Ready:          endpointReady("tcp", "127.0.0.1:443", shimReadyLimit),
		PIDFile:        boot.ShimPIDPath,
	}); err != nil {
		return err
	}
	bootCommand := hardenedCommand(
		hardening.ServiceBoot, boot.BootBinary,
		fmt.Sprintf("--debug=%t", deps.cmdline.Debug),
	)
	bootCommand = withSecretHandoff(bootCommand, secretHandoff)
	if err := deps.oneShot(bootCtx, bootCommand); err != nil {
		return err
	}
	config, err := deps.measuredConfig()
	if err != nil {
		return err
	}
	if err := startVolumeWorkers(bootCtx, deps, config); err != nil {
		return fmt.Errorf("storage volumes: %w", err)
	}
	if err := ownSealRegister(config); err != nil {
		return fmt.Errorf("seal register: %w", err)
	}
	containersCommand := hardenedCommand(hardening.ServiceContainers, boot.ContainersBinary,
		fmt.Sprintf("--debug=%t", deps.cmdline.Debug))
	containersCommand = withSecretHandoff(containersCommand, secretHandoff)
	if err := deps.services.Start(bootCtx, supervisor.Service{
		Name: containersName, Required: true, Restart: true,
		Command: containersCommand,
		Ready:   fileReady(boot.ContainersReadyPath),
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

func withSecretHandoff(command supervisor.Command, handoff *os.File) supervisor.Command {
	childFD := command.AddExtraFile(handoff)
	command.Args = append(command.Args, fmt.Sprintf("--secrets-fd=%d", childFD))
	return command
}

// readMeasuredConfig reads the config tinfoil-boot verified against the hash on
// the kernel command line and wrote to the public ramdisk. That write is part of
// the boot one-shot, which is what makes it readable here: volume workers start
// immediately after it and well before the containers binary, which reads the
// same file for the same reason.
func readMeasuredConfig(debug bool) (*runtimeconfig.Config, error) {
	verified, err := os.ReadFile(boot.ConfigPath)
	if err != nil {
		return nil, err
	}
	return runtimeconfig.Decode(verified, debug)
}

func startVolumeWorkers(ctx context.Context, deps lifecycleDeps, config *runtimeconfig.Config) error {
	if config == nil {
		return nil
	}
	for index, volume := range config.Volumes {
		if volume.KeySecret != "" {
			continue // Boot has already mounted this volume.
		}
		args := []string{
			"--models=" + strconv.Itoa(len(config.Models)),
			"--index=" + strconv.Itoa(index),
			"--name=" + volume.Name,
			fmt.Sprintf("--exec=%t", volume.Exec),
			"--owner=" + volume.Owner,
		}
		for _, overlay := range volume.Overlays {
			args = append(args, "--overlay="+overlay.Model+":"+overlay.Source+":"+overlay.Target)
		}
		command := hardenedCommand(hardening.ServiceVolumes, boot.VolumeWorkerBinary, args...)
		command.Name = volumesName + "-" + volume.Name
		if err := deps.services.Start(ctx, supervisor.Service{
			Name:    command.Name,
			Command: command,
			Ready:   fileReady(filepath.Join(boot.VolumeControlDir, volume.Name, boot.VolumeSocketName)),
		}); err != nil {
			return err
		}
	}
	return nil
}

func ownSealRegister(config *runtimeconfig.Config) error {
	_, owner, ok := runtimeconfig.SealOwner(config)
	if !ok {
		return nil
	}
	return os.Chown(boot.SealRegisterPath, owner, -1)
}

func requiredServiceNames() []string {
	return []string{containerdName, dockerName, containersName, shimName}
}

func shutdownGroups() [][]string {
	return [][]string{
		{shimName},
		{containersName},
		{egressName},
		gpuServiceNames(),
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

func fileReady(path string) func(context.Context) error {
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
	file, err := os.OpenFile("/dev/kmsg", os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		_, _ = fmt.Fprintf(file, kmsgInfoPrefix+"tinfoil-pid1: %s\n", message)
		_ = file.Close()
	}
}
