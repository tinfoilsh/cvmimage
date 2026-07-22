package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tinfoil/internal/egress"
)

type egressRunner interface {
	Configured() bool
	Run(context.Context, func(error))
}

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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return runWith(ctx, func() (egressRunner, error) {
		return egress.Load()
	})
}

func runWith(ctx context.Context, load func() (egressRunner, error)) error {
	engine, err := load()
	if err != nil {
		return err
	}
	if !engine.Configured() {
		log.Println("no allowlist networks configured, exiting")
		return nil
	}
	// Boot owns the readiness-gating initial population. This service only
	// refreshes the already-populated sets at the fixed engine interval.
	engine.Run(ctx, func(err error) {
		log.Printf("refresh failed: %v", err)
	})
	log.Println("shutting down")
	return nil
}
