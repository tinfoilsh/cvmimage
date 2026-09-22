package attestedkeys

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	config "github.com/tinfoilsh/tinfoil-config"
)

func TestGeneratedKeysMatchPublishedInventory(t *testing.T) {
	cfg := &config.Config{AttestedKeys: []config.AttestedKey{
		{ID: "ssh", Key: config.KeyECDSAP256, UID: os.Geteuid(), GID: os.Getegid()},
		{ID: "vpn", Key: config.KeyX25519, UID: os.Geteuid(), GID: os.Getegid()},
	}}
	dir := filepath.Join(t.TempDir(), "keys")
	items, err := Generate(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadPublic(dir, cfg)
	if err != nil || !reflect.DeepEqual(read, items) || items[0].Format != SPKIFormat {
		t.Fatalf("inventory mismatch: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ssh", PrivateFile))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, "ssh", PrivateFile))
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode %v", info.Mode())
	}
	block, _ := pem.Decode(data)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(key.(*ecdsa.PrivateKey).Public())
	if err != nil || hex.EncodeToString(pub) != items[0].Data {
		t.Fatal("endorsed public key does not derive from the private key")
	}
}
