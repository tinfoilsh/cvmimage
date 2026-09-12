package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/identity/permit"
	"tinfoil/internal/secretstore"
	"tinfoil/internal/volume"
)

func run(ctx context.Context, secretFD int) (result error) {
	if secretFD < 0 {
		return errors.New("storage secret descriptor is required")
	}
	source, err := os.ReadFile(bootstate.ConfigPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(volume.PlanPath)
	if err != nil {
		return err
	}
	var plan volume.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	if plan.Digest != secretstore.ConfigDigest(source) {
		return errors.New("storage plan config digest mismatch")
	}
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("invalid storage plan: %w", err)
	}
	fd := os.NewFile(uintptr(secretFD), "storage-secrets")
	keys, err := secretstore.ReadHandoff(fd, plan.Digest, plan.SecretReferences())
	_ = fd.Close()
	if err != nil {
		return err
	}
	externalRaw, err := os.ReadFile(bootstate.ExternalConfigPath)
	if err != nil {
		return err
	}
	external, err := shimconfig.DecodeExternal(externalRaw)
	if err != nil {
		return err
	}
	manager, err := volume.NewManager(plan, keys)
	clear(keys)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, manager.Close()) }()
	if err := os.MkdirAll(filepath.Dir(volume.Socket), 0700); err != nil {
		return err
	}
	listener, err := net.Listen("unix", volume.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(volume.Socket)
	if err := os.Chmod(volume.Socket, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{Handler: handler(manager, external.Env["DOMAIN"], permit.Check), ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		cancel()
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	if err := manager.Initialize(ctx, external.AttachedVolumes); err != nil {
		return fmt.Errorf("initial storage activation: %w", err)
	}
	if err := bootstate.RecordStage(bootstate.StageModels, bootstate.StatusOK, 0, "volume service initialized"); err != nil {
		return err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			// A secret-backed upper may have been waiting for a runtime-unlocked pack.
			if err := manager.OpenInitial(ctx, external.AttachedVolumes); err != nil {
				return err
			}
		}
	}
}
