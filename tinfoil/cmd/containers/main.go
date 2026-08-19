package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/containers"
	"tinfoil/internal/firewall"
	"tinfoil/internal/runtimeconfig"
	"tinfoil/internal/secretstore"
)

const bootPath = "/v1/boot"

type manager struct {
	bootMu         sync.Mutex
	ctx            context.Context
	debug          bool
	verifiedConfig []byte
	secrets        secretstore.Store
}

type invocation struct {
	debug     bool
	secretsFD int
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	log.SetFlags(0)
	invocation, err := parseInvocation(os.Args)
	if err != nil {
		log.Fatalf("tinfoil-containers: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, invocation); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("tinfoil-containers: %v", err)
	}
}

func parseInvocation(args []string) (invocation, error) {
	if len(args) == 0 {
		return invocation{}, fmt.Errorf("missing argv[0]")
	}
	var parsed invocation
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&parsed.debug, "debug", false, "enable the debug boot API")
	flags.IntVar(&parsed.secretsFD, "secrets-fd", -1, "sealed container-secret handoff descriptor")
	if err := flags.Parse(args[1:]); err != nil {
		return invocation{}, err
	}
	if flags.NArg() != 0 {
		return invocation{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	return parsed, nil
}

func run(ctx context.Context, invocation invocation) error {
	if invocation.secretsFD < 0 {
		return fmt.Errorf("container-secret handoff descriptor is required")
	}
	verifiedConfig, err := os.ReadFile(boot.ConfigPath)
	if err != nil {
		return fmt.Errorf("reading verified config: %w", err)
	}
	config, err := runtimeconfig.Decode(verifiedConfig, invocation.debug)
	if err != nil {
		return err
	}
	secretHandoff := os.NewFile(uintptr(invocation.secretsFD), "tinfoil-container-secrets")
	secrets, err := secretstore.ReadHandoff(
		secretHandoff,
		secretstore.ConfigDigest(verifiedConfig),
		secretstore.WorkloadReferences(config),
	)
	if err != nil {
		return err
	}
	if err := secretHandoff.Close(); err != nil {
		return fmt.Errorf("closing container-secret handoff: %w", err)
	}
	if err := os.MkdirAll("/run/tinfoil", 0o700); err != nil {
		return err
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	manager := &manager{
		ctx:            runtimeCtx,
		debug:          invocation.debug,
		verifiedConfig: verifiedConfig,
		secrets:        secrets,
	}

	var listener net.Listener
	if invocation.debug {
		var err error
		listener, err = listenDebugSocket()
		if err != nil {
			return err
		}
		defer listener.Close()
		defer os.Remove(boot.ContainersSocket)
	}

	_ = os.Remove(boot.ContainersReadyPath)
	if _, err := os.Stat(boot.RuntimeBootedPath); errors.Is(err, os.ErrNotExist) {
		if err := manager.boot(nil); err != nil {
			return err
		}
		if err := atomicWrite(boot.RuntimeBootedPath, []byte("booted\n"), 0o600); err != nil {
			return fmt.Errorf("recording runtime boot: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("checking runtime boot marker: %w", err)
	}
	if err := atomicWrite(boot.ContainersReadyPath, []byte("ready\n"), 0o600); err != nil {
		return fmt.Errorf("publishing readiness: %w", err)
	}

	statusDone := make(chan error, 1)
	go func() { statusDone <- containers.RunStatusPublisher(runtimeCtx) }()
	if !invocation.debug {
		return <-statusDone
	}

	mux := http.NewServeMux()
	mux.HandleFunc(bootPath, manager.handleBoot)
	httpServer := &http.Server{Handler: mux}
	go func() {
		<-runtimeCtx.Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	log.Printf("tinfoil-containers: debug API listening on %s", boot.ContainersSocket)
	serveErr := httpServer.Serve(listener)
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	cancel()
	return errors.Join(serveErr, <-statusDone)
}

func listenDebugSocket() (net.Listener, error) {
	_ = os.Remove(boot.ContainersSocket)
	listener, err := net.Listen("unix", boot.ContainersSocket)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", boot.ContainersSocket, err)
	}
	if err := os.Chmod(boot.ContainersSocket, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (m *manager) handleBoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	override, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := m.boot(override); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := containers.PublishStatus(m.ctx); err != nil {
		log.Printf("container status publish failed after debug boot: %v", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *manager) boot(override []byte) (result error) {
	m.bootMu.Lock()
	defer m.bootMu.Unlock()

	source := override
	if len(source) == 0 {
		source = m.verifiedConfig
	}
	config, err := runtimeconfig.Decode(source, m.debug)
	if err != nil {
		return err
	}
	externalData, err := os.ReadFile(boot.ExternalConfigPath)
	if err != nil {
		return fmt.Errorf("reading external config: %w", err)
	}
	external, err := shimconfig.DecodeExternal(externalData)
	if err != nil {
		return err
	}
	secretValues := m.secrets
	if m.debug {
		// Debug users may request any customer-supplied external secret.
		secretValues = secretstore.Store(external.Secrets)
	}
	previous, err := loadRuntimeConfig()
	if err != nil {
		return fmt.Errorf("reading installed config: %w", err)
	}
	preserved := map[string]bool{}
	if previous != nil && runtimeconfig.HasReservedDebugContainer(previous) {
		if !runtimeconfig.HasReservedDebugContainer(config) {
			return errors.New("debug config must retain tinfoil-debug-toolbox")
		}
		preserved[runtimeconfig.ReservedDebugContainerName] = true
	}
	frozenEgress, err := freezeFromPIDFile(boot.EgressPIDPath)
	if err != nil {
		return fmt.Errorf("freezing current egress policy: %w", err)
	}
	if frozenEgress != nil {
		defer frozenEgress.close()
	}
	defer func() {
		if frozenEgress != nil {
			if err := restartFrozenFromPIDFile(context.Background(), boot.EgressPIDPath, frozenEgress); err != nil {
				result = errors.Join(result, fmt.Errorf("restoring egress policy service: %w", err))
			}
		}
	}()
	if err := containers.RemoveManagedExcept(m.ctx, previous, preserved); err != nil {
		return err
	}
	if err := writeRuntimeArtifacts(config, source); err != nil {
		return err
	}
	tracker, err := boot.ResumeTracker()
	if err != nil {
		return err
	}
	start := time.Now()
	if err := firewall.ApplyInbound(config.CVMNetwork.InboundPorts); err != nil {
		tracker.Record(boot.StageFirewall, boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	if err := containers.PrepareNetworks(m.ctx, config, m.debug); err != nil {
		tracker.Record(boot.StageFirewall, boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("preparing container networks: %w", err)
	}
	tracker.Record(boot.StageFirewall, boot.StatusOK, time.Since(start), "")
	if err := restartFrozenFromPIDFile(m.ctx, boot.EgressPIDPath, frozenEgress); err != nil {
		return fmt.Errorf("restarting egress policy: %w", err)
	}
	frozenEgress = nil
	if err := containers.LaunchAndWaitHealthyExcept(m.ctx, tracker, config, external, secretValues, m.debug, preserved); err != nil {
		return err
	}
	return restartRuntimeServices(m.ctx)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
}
