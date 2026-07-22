package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tinfoil/internal/egress"
)

func init() {
	log.SetFlags(0)
}

func main() {
	if err := run(); err != nil {
		log.Printf("tinfoil-egress: %v", err)
		os.Exit(1)
	}
}

func run() error {
	engine, err := egress.Load()
	if err != nil {
		return err
	}
	if !engine.Configured() {
		log.Println("no allowlist networks configured, exiting")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := engine.Populate(ctx); err != nil {
		return fmt.Errorf("initial population: %w", err)
	}

	engine.Run(ctx, func(err error) {
		log.Printf("refresh failed: %v", err)
	})
	log.Println("shutting down")
	return nil
}
