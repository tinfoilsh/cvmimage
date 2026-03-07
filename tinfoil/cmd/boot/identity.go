package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

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

	hpkeKeyFile := shimCfg.HPKEKeyFile
	if hpkeKeyFile == "" {
		hpkeKeyFile = boot.HPKEKeyPath
	}
	serverIdentity, err := identity.FromFile(hpkeKeyFile)
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
