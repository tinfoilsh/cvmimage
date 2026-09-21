// Package attestedkeys owns the per-boot workload key store. The store lives in
// private tmpfs; only explicitly granted key directories are mounted into
// containers. Application encodings and protocols belong to consumers.
package attestedkeys

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	config "github.com/tinfoilsh/tinfoil-config"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

// SPKIFormat carries full DER, unlike the built-in TLS fingerprint format.
const SPKIFormat = "https://tinfoil.sh/key/spki/v1"

const (
	PrivateFile  = "private_key.pem"
	PublicFile   = "public_key.pem"
	manifestFile = "inventory.json"
)

type binding struct {
	Key       config.AttestedKey `json:"key"`
	Container string             `json:"container"`
}

type inventory struct {
	Version  int                           `json:"version"`
	Bindings []binding                     `json:"bindings"`
	Items    []envelope.CryptoMaterialItem `json:"items"`
}

func bindings(cfg *config.Config) ([]binding, error) {
	if err := config.ValidateAttestedKeys(cfg); err != nil {
		return nil, err
	}
	grants := make(map[string]string)
	for _, c := range cfg.Containers {
		for _, id := range c.Keys {
			grants[id] = c.Name
		}
	}
	result := make([]binding, 0, len(cfg.AttestedKeys))
	for _, key := range cfg.AttestedKeys {
		result = append(result, binding{key, grants[key.ID]})
	}
	return result, nil
}

// Ensure generates exactly once, publishing the complete inventory with one
// directory rename. An existing store must match the measured declarations,
// grants, ownership, and key pairs. It is never repaired or partially rotated.
func Ensure(dir string, cfg *config.Config) ([]envelope.CryptoMaterialItem, error) {
	wanted, err := bindings(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(dir); err == nil {
		return load(dir, wanted, true)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(filepath.Dir(dir), ".attested-keys-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	inv := inventory{Version: 1, Bindings: wanted, Items: make([]envelope.CryptoMaterialItem, 0, len(wanted))}
	for _, grant := range wanted {
		key := grant.Key
		private, public, err := generate(key.Key)
		if err != nil {
			return nil, fmt.Errorf("generating attested key %q: %w", key.ID, err)
		}
		keyDir := filepath.Join(staging, key.ID)
		if err := os.Mkdir(keyDir, 0700); err != nil {
			return nil, err
		}
		for _, file := range []struct {
			name, kind string
			data       []byte
			mode       os.FileMode
		}{
			{PrivateFile, "PRIVATE KEY", private, 0600},
			{PublicFile, "PUBLIC KEY", public, 0644},
		} {
			path := filepath.Join(keyDir, file.name)
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: file.kind, Bytes: file.data}), file.mode); err != nil {
				return nil, err
			}
			// Set exact measured permissions even under a restrictive umask.
			if err := os.Chmod(path, file.mode); err != nil {
				return nil, err
			}
			if err := os.Chown(path, key.UID, key.GID); err != nil {
				return nil, err
			}
		}
		if err := os.Chown(keyDir, key.UID, key.GID); err != nil {
			return nil, err
		}
		inv.Items = append(inv.Items, envelope.CryptoMaterialItem{ID: key.ID, Format: SPKIFormat, Data: hex.EncodeToString(public)})
	}
	data, err := json.Marshal(inv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, manifestFile), data, 0600); err != nil {
		return nil, err
	}
	if err := os.Rename(staging, dir); err != nil {
		// A concurrent boot retry may have published first. Only accept a
		// complete matching winner, never overwrite it.
		if _, statErr := os.Lstat(dir); statErr != nil {
			return nil, err
		}
	}
	return load(dir, wanted, true)
}

// LoadPublic is the shim handoff. It checks the committed public inventory and
// measured bindings without entering workload-owned key directories. The shim
// intentionally has no DAC override capability; boot validates the key files.
func LoadPublic(dir string, cfg *config.Config) ([]envelope.CryptoMaterialItem, error) {
	wanted, err := bindings(cfg)
	if err != nil {
		return nil, err
	}
	return load(dir, wanted, false)
}

func load(dir string, wanted []binding, private bool) ([]envelope.CryptoMaterialItem, error) {
	if err := checkPath(dir, 0700, true, os.Geteuid(), os.Getegid()); err != nil {
		return nil, err
	}
	manifest := filepath.Join(dir, manifestFile)
	if err := checkPath(manifest, 0600, false, os.Geteuid(), os.Getegid()); err != nil {
		return nil, err
	}
	f, err := os.Open(manifest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	var inv inventory
	if err := decoder.Decode(&inv); err != nil {
		return nil, fmt.Errorf("invalid attested key inventory: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing attested key inventory data")
	}
	if inv.Version != 1 || !reflect.DeepEqual(inv.Bindings, wanted) || len(inv.Items) != len(wanted) {
		return nil, fmt.Errorf("attested key inventory does not match measured declarations and grants")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) != len(wanted)+1 {
		return nil, fmt.Errorf("unexpected files in attested key store")
	}
	for i, grant := range wanted {
		key, item := grant.Key, inv.Items[i]
		if item.ID != key.ID || item.Format != SPKIFormat {
			return nil, fmt.Errorf("attested key %q does not match inventory", key.ID)
		}
		if err := ValidatePublic(item.Data, key.Key); err != nil {
			return nil, fmt.Errorf("attested key %q: %w", key.ID, err)
		}
		keyDir := filepath.Join(dir, key.ID)
		if err := checkPath(keyDir, 0700, true, key.UID, key.GID); err != nil {
			return nil, err
		}
		if !private {
			continue
		}
		files, err := os.ReadDir(keyDir)
		if err != nil {
			return nil, err
		}
		if len(files) != 2 {
			return nil, fmt.Errorf("incomplete attested key %q", key.ID)
		}
		if err := checkPath(filepath.Join(keyDir, PrivateFile), 0600, false, key.UID, key.GID); err != nil {
			return nil, err
		}
		if err := checkPath(filepath.Join(keyDir, PublicFile), 0644, false, key.UID, key.GID); err != nil {
			return nil, err
		}
		public, err := readPEM(filepath.Join(keyDir, PublicFile), "PUBLIC KEY")
		if err != nil {
			return nil, err
		}
		if item.Data != hex.EncodeToString(public) {
			return nil, fmt.Errorf("public key %q does not match inventory", key.ID)
		}
		der, err := readPEM(filepath.Join(keyDir, PrivateFile), "PRIVATE KEY")
		if err != nil {
			return nil, err
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("invalid private key %q", key.ID)
		}
		var derived crypto.PublicKey
		switch k := parsed.(type) {
		case *ecdsa.PrivateKey:
			derived = k.Public()
		case ed25519.PrivateKey:
			derived = k.Public()
		case *ecdh.PrivateKey:
			derived = k.PublicKey()
		default:
			return nil, fmt.Errorf("unsupported private key %q", key.ID)
		}
		encoded, err := x509.MarshalPKIXPublicKey(derived)
		if err != nil || !bytes.Equal(encoded, public) {
			return nil, fmt.Errorf("private/public key mismatch for %q", key.ID)
		}
	}
	return inv.Items, nil
}

func checkPath(path string, mode os.FileMode, directory bool, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != mode {
		return fmt.Errorf("unsafe attested key path or permissions: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return fmt.Errorf("incorrect attested key ownership: %s", path)
	}
	return nil
}

func readPEM(path, kind string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid %s PEM: %s", kind, path)
	}
	return block.Bytes, nil
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

// ValidatePublic enforces canonical, lowercase full-SPKI encoding and an
// optional measured algorithm. An empty algorithm accepts any supported key.
func ValidatePublic(data, algorithm string) error {
	if len(data) > 2048 || data != strings.ToLower(data) {
		return fmt.Errorf("invalid SPKI hex")
	}
	der, err := hex.DecodeString(data)
	if err != nil {
		return fmt.Errorf("invalid SPKI hex")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("invalid SPKI DER")
	}
	var actual string
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			actual = config.KeyECDSAP256
		}
	case ed25519.PublicKey:
		actual = config.KeyEd25519
	case *ecdh.PublicKey:
		if key.Curve() == ecdh.X25519() {
			actual = config.KeyX25519
		}
	}
	encoded, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || actual == "" || (algorithm != "" && actual != algorithm) || !bytes.Equal(encoded, der) {
		return fmt.Errorf("unsupported or noncanonical public key")
	}
	return nil
}
