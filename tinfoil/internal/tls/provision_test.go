package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
)

func TestWithHTTP01FirewallUsesFixedMeasuredChain(t *testing.T) {
	var events []string
	wantCert := &tls.Certificate{}

	cert, err := withHTTP01FirewallWith(func(script string) error {
		events = append(events, script)
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
		"add rule inet tinfoil http01 tcp dport 80 accept\n",
		"request certificate",
		"flush chain inet tinfoil http01\n",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestWithHTTP01FirewallDoesNotRequestCertificateWhenOpeningFails(t *testing.T) {
	openErr := errors.New("open failed")
	requested := false

	_, err := withHTTP01FirewallWith(func(script string) error {
		if script != "add rule inet tinfoil http01 tcp dport 80 accept\n" {
			t.Fatalf("script = %q", script)
		}
		return openErr
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

	cert, err := withHTTP01FirewallWith(func(string) error {
		call++
		if call == 2 {
			return cleanupErr
		}
		return nil
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

	_, err := withHTTP01FirewallWith(func(string) error {
		call++
		if call == 2 {
			return cleanupErr
		}
		return nil
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

func TestProvisionReturnsCertificateForAttestedKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := Provision(context.Background(), Request{Domain: "localhost", Key: key, HPKEKey: make([]byte, 32)}, &shimconfig.Config{TLSMode: "self-signed"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) || cert.PrivateKey != key {
		t.Fatal("certificate key differs from attested key")
	}
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificateForKey(cert, other); err == nil {
		t.Fatal("cached certificate for another identity accepted")
	}
}

func TestCertificateRetryStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := retryCertificate(ctx, func() (*tls.Certificate, error) {
		calls++
		cancel()
		return nil, errors.New("temporary failure")
	}, time.Hour)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls = %d, error = %v", calls, err)
	}
}
