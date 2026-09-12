package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	configdecode "tinfoil/internal/runtimeconfig"
	"tinfoil/internal/volume"
	"tinfoil/sandbox/internal/variant"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("tinfoil-sandbox: %v", err)
	}
}

func run() (result error) {
	start := time.Now()
	defer func() {
		if result != nil {
			_ = bootstate.RecordStage(variant.Stage, bootstate.StatusFailed, time.Since(start), result.Error())
		}
	}()
	syscall.Umask(0o077)

	config, err := measuredConfig()
	if err != nil {
		return err
	}

	domain, err := externalDomain()
	if err != nil {
		return err
	}
	permit, err := publicKey(permitKey)
	if err != nil {
		return fmt.Errorf("permit key: %w", err)
	}
	state, err := (volume.Client{}).Status(context.Background())
	if err != nil {
		return err
	}
	workspaceName, _, err := runtimeconfig.WorkspaceRoles(config)
	if err != nil {
		return err
	}
	box := &sandbox{
		domain:    domain,
		permit:    permit,
		nonce:     state.Nonce,
		workspace: workspaceName,
	}

	if err := box.prepare(); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listener, err := net.Listen("tcp", variant.APIAddress)
	if err != nil {
		return err
	}
	if err := bootstate.RecordStage(variant.Stage, bootstate.StatusOK, time.Since(start), "API listening"); err != nil {
		listener.Close()
		return err
	}

	server := &http.Server{
		Handler:           box.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("shutdown failed: %v", err)
		}
	}()

	log.Printf("sandbox %s serving boot %s, awaiting enrollment", box.domain, box.nonce)
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func measuredConfig() (*runtimeconfig.Config, error) {
	data, err := os.ReadFile(bootstate.ConfigPath)
	if err != nil {
		return nil, err
	}
	config, err := configdecode.Decode(data, false)
	if err != nil {
		return nil, err
	}
	if _, _, err := runtimeconfig.WorkspaceRoles(config); err != nil {
		return nil, err
	}
	return config, nil
}

func externalDomain() (string, error) {
	data, err := os.ReadFile(bootstate.ExternalConfigPath)
	if err != nil {
		return "", err
	}
	external, err := shimconfig.DecodeExternal(data)
	if err != nil {
		return "", err
	}
	if external.Env["DOMAIN"] == "" {
		return "", errors.New("DOMAIN is not set in the external config")
	}
	return external.Env["DOMAIN"], nil
}
