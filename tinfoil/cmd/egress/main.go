package main

import (
	"context"
	"fmt"
	"log"
	"net"
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

	// Initial population must succeed before notifying systemd; tinfoil-boot
	// blocks on `systemctl start` until READY=1 so any failure here surfaces
	// as a boot error.
	if err := engine.Populate(ctx); err != nil {
		return fmt.Errorf("initial population: %w", err)
	}
	notifyReady()

	engine.Run(ctx, func(err error) {
		log.Printf("refresh failed: %v", err)
	})
	log.Println("shutting down")
	return nil
}

// notifyReady sends READY=1 over the systemd NOTIFY_SOCKET so the unit
// transitions to active only after the first successful resolution. No-op
// when not running under systemd Type=notify (NOTIFY_SOCKET unset).
func notifyReady() {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		log.Printf("sd_notify dial: %v", err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		log.Printf("sd_notify write: %v", err)
	}
}
