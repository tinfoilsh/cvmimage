package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	ehbp "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"tinfoil/internal/attestation"
	tlsutil "tinfoil/internal/tls"
)

// Node holds the cryptographic identity generated during boot.
type Node struct {
	TLSKey       *ecdsa.PrivateKey
	HPKEKeyBytes []byte
	Domain       string
}

const x25519PublicKeySize = 32

func Generate(domain string, dummy bool, hpkePath string) (*Node, error) {
	if domain == "" && !dummy {
		return nil, fmt.Errorf("DOMAIN not set in external config (set dummy-attestation: true for local dev)")
	}
	if domain == "" {
		domain = "localhost"
	}

	serverIdentity, err := loadOrCreateHPKEIdentity(hpkePath)
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
	return &Node{
		TLSKey:       privateKey,
		HPKEKeyBytes: hpkeKeyBytes,
		Domain:       domain,
	}, nil
}

// loadOrCreateHPKEIdentity returns the HPKE identity at path, generating and
// persisting a new one with mode 0600 when the file does not yet exist.
// ehbp.FromFile would create a fresh key world-readable (0644).
func loadOrCreateHPKEIdentity(path string) (*ehbp.Identity, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		i, err := ehbp.NewIdentity()
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
	return ehbp.FromFile(path)
}

// Body binds the public keys used by TLS and encrypted HTTP to attestation.
func (id *Node) Body() attestation.BodyV2 {
	var hpkeKey [32]byte
	copy(hpkeKey[:], id.HPKEKeyBytes)
	return attestation.BodyV2{TLSKeyFP: tlsutil.KeyFPBytes(&id.TLSKey.PublicKey), HPKEKey: hpkeKey}
}
