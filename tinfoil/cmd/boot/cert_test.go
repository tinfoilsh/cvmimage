package main

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/dcode"
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

func TestMeasuredFirewallDefinesHTTP01Chain(t *testing.T) {
	policyPath := filepath.Join("..", "..", "..", "image", "rootfs", "etc", "nftables.conf")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("reading %s: %v", policyPath, err)
	}

	text := string(policy)
	for _, contract := range []string{
		"chain http01 {\n    }",
		"jump http01",
		"ip protocol 1 accept",
		"meta l4proto 58 accept",
	} {
		if !strings.Contains(text, contract) {
			t.Fatalf("measured firewall policy does not contain %q", contract)
		}
	}
	if strings.Contains(text, "tcp dport 80 accept") {
		t.Fatal("measured firewall policy opens HTTP-01 before certificate issuance")
	}
	for _, protocolName := range []string{"ip protocol icmp", "l4proto ipv6-icmp"} {
		if strings.Contains(text, protocolName) {
			t.Fatalf("measured firewall policy depends on protocol-name parsing: %q", protocolName)
		}
	}
}

func TestCertificateDomainsKeepHPKEWithoutLegacyAttestation(t *testing.T) {
	id := &NodeIdentity{Domain: "enclave.example.com", HPKEKeyBytes: []byte("public HPKE key")}
	for _, ownDomain := range []bool{false, true} {
		for _, wildcard := range []bool{false, true} {
			config := &shimconfig.Config{TLSMode: "cert-proxy", TLSChallengeMode: "dns", TLSOwnSANDomain: ownDomain, TLSWildcard: wildcard, PublishAttestation: true}
			domains, err := certificateDomains(id, config)
			if err != nil {
				t.Fatal(err)
			}
			suffix := "hpke.tinfoil.sh"
			if ownDomain {
				suffix = "hpke.example.com"
			}
			encoded, err := dcode.Encode(id.HPKEKeyBytes, suffix)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{id.Domain}
			if wildcard {
				want = append(want, "*."+id.Domain)
			}
			want = append(want, encoded...)
			if !reflect.DeepEqual(domains, want) {
				t.Fatalf("certificate domains = %v, want %v", domains, want)
			}
			config.TLSMode, config.TLSChallengeMode = "acme", "http"
			domains, err = certificateDomains(id, config)
			if err != nil || !reflect.DeepEqual(domains, []string{id.Domain}) {
				t.Fatalf("HTTP-01 certificate domains = %v, %v", domains, err)
			}
		}
	}
}
