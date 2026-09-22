// Package attestedkeys generates the per-boot workload keys that containers
// receive as read-only file mounts and that every v3 quote endorses.
package attestedkeys

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	config "github.com/tinfoilsh/tinfoil-config"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

// SPKIFormat carries full DER, unlike the built-in TLS fingerprint format.
const SPKIFormat = "https://tinfoil.sh/key/spki/v1"

const (
	privateFile = "private_key.pem"
	publicFile  = "public_key.pem"
)

// Generate writes every declared key pair under dir and returns the public
// inventory.
func Generate(dir string, cfg *config.Config) ([]envelope.CryptoMaterialItem, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	for _, key := range cfg.AttestedKeys {
		private, public, err := generate(key.Key)
		if err != nil {
			return nil, fmt.Errorf("generating attested key %q: %w", key.ID, err)
		}
		keyDir := filepath.Join(dir, key.ID)
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return nil, err
		}
		for _, file := range []struct {
			name, kind string
			data       []byte
			mode       os.FileMode
		}{
			{privateFile, "PRIVATE KEY", private, 0600},
			{publicFile, "PUBLIC KEY", public, 0644},
		} {
			path := filepath.Join(keyDir, file.name)
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: file.kind, Bytes: file.data}), file.mode); err != nil {
				return nil, err
			}
			if err := os.Chown(path, key.UID, key.GID); err != nil {
				return nil, err
			}
		}
		if err := os.Chown(keyDir, key.UID, key.GID); err != nil {
			return nil, err
		}
	}
	return ReadPublic(dir)
}

// ReadPublic returns the endorsed inventory of every key stored under dir.
func ReadPublic(dir string) ([]envelope.CryptoMaterialItem, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	items := make([]envelope.CryptoMaterialItem, 0, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name(), publicFile))
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("invalid public key for attested key %q", entry.Name())
		}
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("attested key %q: %w", entry.Name(), err)
		}
		items = append(items, envelope.CryptoMaterialItem{ID: entry.Name(), Format: SPKIFormat, Data: hex.EncodeToString(block.Bytes)})
	}
	return items, nil
}

func generate(algorithm string) ([]byte, []byte, error) {
	var private any
	var public crypto.PublicKey
	switch algorithm {
	case config.KeyECDSAP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		private, public = key, key.Public()
	case config.KeyEd25519:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		private, public = key, pub
	case config.KeyX25519:
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		private, public = key, key.PublicKey()
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(public)
	return priv, pub, err
}
