package main

import (
	"context"
	"crypto/tls"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestWithHTTP01FirewallUsesFixedMeasuredChain(t *testing.T) {
	var events []string
	wantCert := &tls.Certificate{}

	cert, err := withHTTP01FirewallWith(func(context.Context) error {
		events = append(events, "open")
		return nil
	}, func(context.Context) error {
		events = append(events, "close")
		return nil
	}, func() (*tls.Certificate, error) {
		events = append(events, "request certificate")
		return wantCert, nil
	})
	if err != nil {
		t.Fatalf("withHTTP01FirewallWith() error = %v", err)
	}
	if cert != wantCert {
		t.Fatalf("withHTTP01FirewallWith() certificate = %p, want %p", cert, wantCert)
	}

	wantEvents := []string{
		"open",
		"request certificate",
		"close",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestWithHTTP01FirewallDoesNotRequestCertificateWhenOpeningFails(t *testing.T) {
	openErr := errors.New("open failed")
	requested := false

	_, err := withHTTP01FirewallWith(func(context.Context) error {
		return openErr
	}, func(context.Context) error {
		t.Fatal("close called after open failure")
		return nil
	}, func() (*tls.Certificate, error) {
		requested = true
		return nil, nil
	})
	if !errors.Is(err, openErr) {
		t.Fatalf("error = %v, want wrapped %v", err, openErr)
	}
	if requested {
		t.Fatal("certificate request ran after firewall opening failed")
	}
}

func TestWithHTTP01FirewallFailsClosedWhenCleanupFails(t *testing.T) {
	cleanupErr := errors.New("flush failed")
	call := 0

	cert, err := withHTTP01FirewallWith(func(context.Context) error {
		call++
		return nil
	}, func(context.Context) error {
		call++
		return cleanupErr
	}, func() (*tls.Certificate, error) {
		return &tls.Certificate{}, nil
	})
	if cert == nil {
		t.Fatal("certificate = nil")
	}
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("error = %v, want wrapped %v", err, cleanupErr)
	}
	if !strings.Contains(err.Error(), "closing HTTP-01 firewall") {
		t.Fatalf("error = %q, want cleanup context", err)
	}
}

func TestWithHTTP01FirewallPreservesRequestAndCleanupFailures(t *testing.T) {
	requestErr := errors.New("request failed")
	cleanupErr := errors.New("flush failed")
	call := 0

	_, err := withHTTP01FirewallWith(func(context.Context) error {
		call++
		return nil
	}, func(context.Context) error {
		call++
		return cleanupErr
	}, func() (*tls.Certificate, error) {
		return nil, requestErr
	})
	if !errors.Is(err, requestErr) {
		t.Fatalf("error = %v, want wrapped %v", err, requestErr)
	}
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("error = %v, want wrapped %v", err, cleanupErr)
	}
}
