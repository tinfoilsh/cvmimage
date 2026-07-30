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

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/containers"
	"tinfoil/internal/containersapi"
	"tinfoil/internal/firewall"
	"tinfoil/internal/kernelcmdline"
	"tinfoil/internal/runtimeconfig"
)

type server struct {
	bootMu sync.Mutex
	ctx    context.Context
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
	_ = os.Remove(boot.ContainersSocket)
	listener, err := net.Listen("unix", boot.ContainersSocket)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", boot.ContainersSocket, err)
	}
	defer listener.Close()
	defer os.Remove(boot.ContainersSocket)
	if err := os.Chmod(boot.ContainersSocket, 0o660); err != nil {
		return err
	}

	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	handler := &server{ctx: runtimeCtx}
	mux := http.NewServeMux()
	mux.HandleFunc(containersapi.BootPath, handler.boot)
	httpServer := &http.Server{Handler: mux}
	statusDone := make(chan error, 1)
	go func() { statusDone <- containers.RunStatusPublisher(runtimeCtx); cancel() }()
	go func() { <-runtimeCtx.Done(); _ = httpServer.Shutdown(context.Background()) }()
	log.Printf("tinfoil-containers: listening on %s", boot.ContainersSocket)
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	cancel()
	return errors.Join(err, <-statusDone)
}

func (s *server) boot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.bootMu.Lock()
	defer s.bootMu.Unlock()

	override, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	debug, err := kernelcmdline.DebugEnabled()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(override) > 0 && !debug {
		writeError(w, http.StatusForbidden, errors.New("config overrides require tinfoil-debug=on"))
		return
	}
	source := override
	if len(source) == 0 {
		source, err = os.ReadFile(boot.ConfigPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("reading verified config: %w", err))
			return
		}
	}
	config, err := runtimeconfig.Decode(source, debug)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	externalData, err := os.ReadFile(boot.ExternalConfigPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("reading external config: %w", err))
		return
	}
	external, err := shimconfig.DecodeExternal(externalData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	previous, err := loadRuntimeConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("reading installed config: %w", err))
		return
	}
	preserved := map[string]bool{}
	if previous != nil && debug && runtimeconfig.HasReservedDebugContainer(previous) {
		if !runtimeconfig.HasReservedDebugContainer(config) {
			writeError(w, http.StatusBadRequest, errors.New("debug config must retain tinfoil-debug-toolbox"))
			return
		}
		preserved[runtimeconfig.ReservedDebugContainerName] = true
	}
	if err := containers.RemoveManagedExcept(s.ctx, previous, preserved); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := writeRuntimeArtifacts(config, source); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := firewall.ApplyInbound(config.CVMNetwork.InboundPorts); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	launchConfig := config
	if preserved[runtimeconfig.ReservedDebugContainerName] {
		copy := *config
		copy.Containers = nil
		for _, container := range config.Containers {
			if container.Name != runtimeconfig.ReservedDebugContainerName {
				copy.Containers = append(copy.Containers, container)
			}
		}
		launchConfig = &copy
	}
	tracker, err := boot.ResumeTracker()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := containers.LaunchAndWaitHealthy(s.ctx, tracker, launchConfig, external, debug); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := restartRuntimeServices(s.ctx); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(containersapi.ErrorResponse{Error: err.Error()})
}
