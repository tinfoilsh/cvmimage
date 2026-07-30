package main

import (
	"context"
	"encoding/json"
	"errors"
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
	"tinfoil/internal/kernelcmdline"
	"tinfoil/internal/runtimeconfig"
)

const bootPath = "/v1/boot"

type manager struct {
	bootMu sync.Mutex
	ctx    context.Context
	debug  bool
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("tinfoil-containers: %v", err)
	}
}

func run(ctx context.Context) error {
	if err := os.MkdirAll("/run/tinfoil", 0o700); err != nil {
		return err
	}
	debug, err := kernelcmdline.DebugEnabled()
	if err != nil {
		return err
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	manager := &manager{ctx: runtimeCtx, debug: debug}

	var listener net.Listener
	if debug {
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
	if !debug {
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

func (m *manager) boot(override []byte) error {
	m.bootMu.Lock()
	defer m.bootMu.Unlock()

	source := override
	if len(source) == 0 {
		var err error
		source, err = os.ReadFile(boot.ConfigPath)
		if err != nil {
			return fmt.Errorf("reading verified config: %w", err)
		}
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
	if err := containers.RemoveManagedExcept(m.ctx, previous, preserved); err != nil {
		return err
	}
	if err := writeRuntimeArtifacts(config, source); err != nil {
		return err
	}
	launchConfig := withoutPreservedContainers(config, preserved)
	tracker, err := boot.ResumeTracker()
	if err != nil {
		return err
	}
	start := time.Now()
	if err := firewall.ApplyInbound(config.CVMNetwork.InboundPorts); err != nil {
		tracker.Record(boot.StageFirewall, boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record(boot.StageFirewall, boot.StatusOK, time.Since(start), "")
	if err := containers.LaunchAndWaitHealthy(m.ctx, tracker, launchConfig, external, m.debug); err != nil {
		return err
	}
	return restartRuntimeServices(m.ctx)
}

func withoutPreservedContainers(config *runtimeconfig.Config, preserved map[string]bool) *runtimeconfig.Config {
	if len(preserved) == 0 {
		return config
	}
	copy := *config
	copy.Containers = nil
	for _, container := range config.Containers {
		if !preserved[container.Name] {
			copy.Containers = append(copy.Containers, container)
		}
	}
	return &copy
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
}
