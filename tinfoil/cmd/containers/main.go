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
	"tinfoil/internal/containerapi"
	"tinfoil/internal/containers"
	"tinfoil/internal/containerstatus"
	"tinfoil/internal/runtimeconfig"
)

type server struct {
	applyMu sync.Mutex
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

	handler := &server{}
	mux := http.NewServeMux()
	mux.HandleFunc(containerapi.ApplyPath, handler.apply)
	httpServer := &http.Server{Handler: mux}
	statusDone := make(chan error, 1)
	go func() { statusDone <- containerstatus.Run(ctx) }()
	go func() {
		<-ctx.Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	log.Printf("tinfoil-containers: listening on %s", boot.ContainersSocket)
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	select {
	case statusErr := <-statusDone:
		return errors.Join(err, statusErr)
	default:
		return err
	}
}

func (s *server) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	decoder.DisallowUnknownFields()
	var request containerapi.ApplyRequest
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
	if err := containers.LaunchAndWaitHealthy(r.Context(), tracker, &config, &external, request.Debug); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(containerapi.ErrorResponse{Error: err.Error()})
}
