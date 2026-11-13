package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"sync/atomic"

	sharedconfig "github.com/tinfoilsh/tinfoil-config"

	shimconfig "tinfoil/internal/config"
)

var connectionDrain atomic.Pointer[shimconfig.Config]

type drainMode uint8

const (
	workloadDrain drainMode = iota
	attestationDrain
)

func serveUntilShutdown(ctx context.Context, srv *http.Server) error {
	return serveHTTPUntilShutdown(ctx, srv, func() error { return srv.ListenAndServeTLS("", "") }, workloadDrain)
}

func serveHTTPUntilShutdown(ctx context.Context, srv *http.Server, serve func() error, mode drainMode) error {
	var active sync.WaitGroup
	handler := srv.Handler
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Done()
		handler.ServeHTTP(w, r)
	})
	served := make(chan error, 1)
	go func() { served <- serve() }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	policy := connectionDrain.Load()
	if mode != attestationDrain && (policy == nil || !policy.DrainConnections) {
		log.Print("Closing connections without draining")
		return srv.Close()
	}
	timeout := sharedconfig.DefaultDrainTimeout
	if policy != nil && policy.DrainTimeout > 0 {
		timeout = policy.DrainTimeout
	}
	log.Print("Draining connections; waiting for in-flight requests")
	drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Shutdown closes idle HTTP/1 connections and sends HTTP/2 GOAWAY.
	// Keep the process (and its upstream dependencies) alive until it finishes.
	if err := srv.Shutdown(drainCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Printf("Connection drain reached its %s timeout", timeout)
			return srv.Close()
		}
		return err
	}
	// ReverseProxy keeps upgraded handlers alive, but Shutdown does not wait
	// for hijacked connections. Preserve those streams until their peers finish.
	finished := make(chan struct{})
	go func() { active.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-drainCtx.Done():
		log.Printf("Connection drain reached its %s timeout", timeout)
		return srv.Close()
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Print("Connection drain complete")
	return nil
}
