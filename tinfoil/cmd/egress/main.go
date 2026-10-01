package main

import (
	"context"
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return egress.New().Run(ctx)
}
