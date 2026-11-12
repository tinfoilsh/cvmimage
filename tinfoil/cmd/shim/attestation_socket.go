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

	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"
	"tinfoil/internal/boot"
)

const (
	noAttestationFD      = -1
	localAttestationPath = attestationPath
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
		switch r.URL.EscapedPath() {
		case localAttestationPath, attestationV3Path, attestationV3Path + "/":
		default:
			writeAPIError(w, errNotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		queryFields := 1
		if formats, withTime := query["format"]; withTime {
			if len(formats) != 1 || formats[0] != attestationTimeVersion || r.URL.Path != localAttestationPath {
				writeAPIError(w, errInvalidAttestationFormat)
				return
			}
			queryFields++
		}
		nonces := query["nonce"]
		if err != nil || len(query) != queryFields || len(nonces) != 1 || len(nonces[0]) != hex.EncodedLen(envelope.NonceSize) || r.ContentLength != 0 {
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

func newLocalControlHandler(next http.Handler, timeReady http.Handler) http.Handler {
	attestation := newLocalAttestationHandler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() == boot.TimeReadyPath {
			timeReady.ServeHTTP(w, r)
			return
		}
		attestation.ServeHTTP(w, r)
	})
}

func serveWithAttestation(ctx context.Context, public *http.Server, listener net.Listener, timeReady http.Handler) error {
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
		Handler:           newLocalControlHandler(public.Handler, timeReady),
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
