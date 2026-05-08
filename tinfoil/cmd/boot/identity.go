package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// NodeIdentity holds the cryptographic identity generated during boot.
type NodeIdentity struct {
	TLSKey       *ecdsa.PrivateKey
	HPKEKeyBytes []byte
	Domain       string
}

const x25519PublicKeySize = 32

func generateIdentity(shimCfg *shimconfig.Config, externalConfig *shimconfig.ExternalConfig) (*NodeIdentity, error) {
	domain := ""
	if externalConfig.Env != nil {
		domain = externalConfig.Env["DOMAIN"]
	}
	if domain == "" && !shimCfg.DummyAttestation {
		return nil, fmt.Errorf("DOMAIN not set in external config (set dummy-attestation: true for local dev)")
	}
	if domain == "" {
		domain = "localhost"
	}

	serverIdentity, err := loadOrCreateHPKEIdentity(boot.HPKEKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading HPKE identity: %w", err)
	}

	hpkeKeyBytes := serverIdentity.MarshalPublicKey()
	if len(hpkeKeyBytes) != x25519PublicKeySize {
		return nil, fmt.Errorf("HPKE key length is %d, expected %d", len(hpkeKeyBytes), x25519PublicKeySize)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating TLS key: %w", err)
	}

	log.Printf("Identity generated: domain=%s", domain)
	return &NodeIdentity{
		TLSKey:       privateKey,
		HPKEKeyBytes: hpkeKeyBytes,
		Domain:       domain,
	}, nil
}

// loadOrCreateHPKEIdentity returns the HPKE identity at path, generating and
// persisting a new one with mode 0600 when the file does not yet exist.
// identity.FromFile would create a fresh key world-readable (0644).
func loadOrCreateHPKEIdentity(path string) (*identity.Identity, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		i, err := identity.NewIdentity()
		if err != nil {
			return nil, fmt.Errorf("creating HPKE identity: %w", err)
		}
		b, err := i.Export()
		if err != nil {
			return nil, fmt.Errorf("exporting HPKE identity: %w", err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, fmt.Errorf("writing HPKE identity: %w", err)
		}
		return i, nil
	}
	return identity.FromFile(path)
}
