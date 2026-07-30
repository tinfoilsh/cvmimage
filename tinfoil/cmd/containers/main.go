package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/containers"
	"tinfoil/internal/firewall"
	"tinfoil/internal/kernelcmdline"
	"tinfoil/internal/runtimeconfig"
)

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
	_ = os.Remove(boot.ContainersReadyPath)
	if _, err := os.Stat(boot.RuntimeBootedPath); errors.Is(err, os.ErrNotExist) {
		if err := bootDefaultRuntime(ctx); err != nil {
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

	return containers.RunStatusPublisher(ctx)
}

func bootDefaultRuntime(ctx context.Context) error {
	debug, err := kernelcmdline.DebugEnabled()
	if err != nil {
		return err
	}
	source, err := os.ReadFile(boot.ConfigPath)
	if err != nil {
		return fmt.Errorf("reading verified config: %w", err)
	}
	config, err := runtimeconfig.Decode(source, debug)
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
	if err := containers.RemoveManagedExcept(ctx, previous, nil); err != nil {
		return err
	}
	if err := writeRuntimeArtifacts(config, source); err != nil {
		return err
	}
	if err := firewall.ApplyInbound(config.CVMNetwork.InboundPorts); err != nil {
		return err
	}
	tracker, err := boot.ResumeTracker()
	if err != nil {
		return err
	}
	return containers.LaunchAndWaitHealthy(ctx, tracker, config, external, debug)
}
