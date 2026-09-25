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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"golang.org/x/time/rate"
)

const (
	noAttestationFD          = -1
	localAttestationPath     = "/.well-known/tinfoil-attestation"
	localAttestationInterval = time.Second
	localAttestationBurst    = 1
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

type localAttestationHandler struct {
	next    http.Handler
	limiter *rate.Limiter
	active  atomic.Bool
	now     func() time.Time
}

func newLocalAttestationHandler(next http.Handler) *localAttestationHandler {
	return &localAttestationHandler{
		next:    next,
		limiter: rate.NewLimiter(rate.Every(localAttestationInterval), localAttestationBurst),
		now:     time.Now,
	}
}

func (h *localAttestationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if !h.active.CompareAndSwap(false, true) {
		h.reject(w)
		return
	}
	defer h.active.Store(false)
	if !h.limiter.AllowN(h.now(), 1) {
		h.reject(w)
		return
	}
	h.next.ServeHTTP(w, r)
}

func (h *localAttestationHandler) reject(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(localAttestationInterval)))
	writeAPIError(w, errRateLimited)
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
