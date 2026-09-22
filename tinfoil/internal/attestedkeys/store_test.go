package attestedkeys

import (
	"crypto"
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
	uid, gid := os.Geteuid(), os.Getegid()
	cfg := &config.Config{AttestedKeys: []config.AttestedKey{
		{ID: "ssh", Key: config.KeyECDSAP256, UID: uid, GID: gid},
		{ID: "sign", Key: config.KeyEd25519, UID: uid, GID: gid},
		{ID: "vpn", Key: config.KeyX25519, UID: uid, GID: gid},
	}}
	dir := filepath.Join(t.TempDir(), "keys")
	items, err := Generate(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadPublic(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read, items) || len(items) != len(cfg.AttestedKeys) {
		t.Fatalf("inventory mismatch: %v vs %v", read, items)
	}
	for _, item := range items {
		path := filepath.Join(dir, item.ID, privateFile)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s: private key mode %v", item.ID, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatalf("%s: private key is not PEM", item.ID)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.MarshalPKIXPublicKey(key.(interface{ Public() crypto.PublicKey }).Public())
		if err != nil {
			t.Fatal(err)
		}
		if item.Format != SPKIFormat || hex.EncodeToString(pub) != item.Data {
			t.Fatalf("%s: endorsed public key does not derive from the private key", item.ID)
		}
	}
}
