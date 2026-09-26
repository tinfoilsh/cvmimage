package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

const (
	noAttestationFD      = -1
	localAttestationPath = "/.well-known/tinfoil-attestation"
)

func inheritedAttestationListener(fd int) (net.Listener, error) {
	if fd == noAttestationFD {
		return nil, nil
	}
	if fd < 0 {
		return nil, fmt.Errorf("invalid attestation listener descriptor %d", fd)
	}
	file := os.NewFile(uintptr(fd), "attestation-listener")
	if file == nil {
		return nil, fmt.Errorf("invalid attestation listener descriptor %d", fd)
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, fmt.Errorf("opening attestation listener: %w", err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok || listener.Addr().Network() != "unix" {
		listener.Close()
		return nil, fmt.Errorf("attestation listener must be a Unix stream socket")
	}
	unixListener.SetUnlinkOnClose(false)
	return unixListener, nil
}

func newLocalAttestationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != localAttestationPath {
			writeAPIError(w, errNotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		nonces := query["nonce"]
		if err != nil || len(query) != 1 || len(nonces) != 1 || len(nonces[0]) != hex.EncodedLen(envelope.NonceSize) || r.ContentLength != 0 {
			writeAPIError(w, errInvalidNonce)
			return
		}
		if _, err := hex.DecodeString(nonces[0]); err != nil {
			writeAPIError(w, errInvalidNonce)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func serveWithAttestation(ctx context.Context, public *http.Server, listener net.Listener) error {
	if listener == nil {
		return serveUntilShutdown(ctx, public)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	local := &http.Server{
		ReadHeaderTimeout: shimReadHeaderTimeout,
		ReadTimeout:       shimReadHeaderTimeout,
		IdleTimeout:       shimIdleTimeout,
		Handler:           newLocalAttestationHandler(public.Handler),
	}
	done := make(chan error, 1)
	go func() {
		done <- serveLocalAttestation(ctx, local, listener)
		cancel()
	}()
	publicErr := serveUntilShutdown(ctx, public)
	cancel()
	return errors.Join(publicErr, <-done)
}

func serveLocalAttestation(ctx context.Context, server *http.Server, listener net.Listener) error {
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	if err := server.Shutdown(context.Background()); err != nil {
		return err
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
