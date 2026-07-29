package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"tinfoil/internal/runtimeconfig"
)

type server struct {
	applyMu     sync.Mutex
	ctx         context.Context
	initialized bool
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
	mux.HandleFunc(containersapi.ApplyPath, handler.apply)
	httpServer := &http.Server{Handler: mux}
	statusDone := make(chan error, 1)
	go func() {
		statusDone <- containers.RunStatusPublisher(runtimeCtx)
		cancel()
	}()
	go func() {
		<-runtimeCtx.Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	log.Printf("tinfoil-containers: listening on %s", boot.ContainersSocket)
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	cancel()
	return errors.Join(err, <-statusDone)
}

func (s *server) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.initialized {
		writeError(w, http.StatusConflict, errors.New("runtime configuration is already initialized"))
		return
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	decoder.DisallowUnknownFields()
	var request containersapi.ApplyRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var config runtimeconfig.Config
	if err := json.Unmarshal(request.Config, &config); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding config: %w", err))
		return
	}
	var external shimconfig.ExternalConfig
	if err := json.Unmarshal(request.ExternalConfig, &external); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding external config: %w", err))
		return
	}
	tracker, err := boot.ResumeTracker()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := containers.LaunchAndWaitHealthy(s.ctx, tracker, &config, &external, request.Debug); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.initialized = true
	w.WriteHeader(http.StatusNoContent)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(containersapi.ErrorResponse{Error: err.Error()})
}
