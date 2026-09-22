package attestedkeys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"

	config "github.com/tinfoilsh/tinfoil-config"
	"golang.org/x/sys/unix"
)

func testConfig() *config.Config {
	return &config.Config{AttestedKeys: []config.AttestedKey{
		{ID: "ssh", Key: config.KeyECDSAP256, UID: os.Geteuid(), GID: os.Getegid()},
		{ID: "signing", Key: config.KeyEd25519, UID: os.Geteuid(), GID: os.Getegid()},
		{ID: "vpn", Key: config.KeyX25519, UID: os.Geteuid(), GID: os.Getegid()},
	}, Containers: []config.Container{{Name: "first", Keys: []string{"ssh", "signing"}}, {Name: "second", Keys: []string{"vpn"}}}}
}

func TestKeyPairsLifecycleAndPublicHandoff(t *testing.T) {
	cfg := testConfig()
	dir := filepath.Join(t.TempDir(), "keys")
	first, err := Ensure(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i, grant := range cfg.AttestedKeys {
		priv, err := readPEM(filepath.Join(dir, grant.ID, PrivateFile), "PRIVATE KEY")
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.ParsePKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pubDER, err := hex.DecodeString(first[i].Data)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			t.Fatal(err)
		}
		message := sha256.Sum256([]byte("boot key proof"))
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			signature, err := ecdsa.SignASN1(rand.Reader, k, message[:])
			if err != nil || !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), message[:], signature) {
				t.Fatal("ECDSA key pair mismatch")
			}
		case ed25519.PrivateKey:
			if !ed25519.Verify(pub.(ed25519.PublicKey), message[:], ed25519.Sign(k, message[:])) {
				t.Fatal("Ed25519 key pair mismatch")
			}
		case *ecdh.PrivateKey:
			peer, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			left, err := peer.ECDH(pub.(*ecdh.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			right, err := k.ECDH(peer.PublicKey())
			if err != nil || !bytes.Equal(left, right) {
				t.Fatal("X25519 key pair mismatch")
			}
		default:
			t.Fatalf("unexpected private key %T", key)
		}
	}
	retry, err := Ensure(dir, cfg)
	if err != nil || !reflect.DeepEqual(first, retry) {
		t.Fatalf("same-boot retry rotated keys: %v", err)
	}
	public, err := LoadPublic(dir, cfg)
	if err != nil || !reflect.DeepEqual(first, public) {
		t.Fatalf("shim handoff differs: %v", err)
	}
	second, err := Ensure(filepath.Join(t.TempDir(), "keys"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		if first[i].Data == second[i].Data {
			t.Fatal("fresh boot reused a key")
		}
	}
}

func TestInvalidStoreFailsWithoutRepair(t *testing.T) {
	for _, mutate := range []struct {
		name  string
		apply func(*testing.T, string, *config.Config)
	}{
		{"missing manifest", func(t *testing.T, dir string, _ *config.Config) { must(t, os.Remove(filepath.Join(dir, manifestFile))) }},
		{"corrupt manifest", func(t *testing.T, dir string, _ *config.Config) {
			must(t, os.WriteFile(filepath.Join(dir, manifestFile), []byte("{}"), 0600))
		}},
		{"missing private", func(t *testing.T, dir string, _ *config.Config) {
			must(t, os.Remove(filepath.Join(dir, "ssh", PrivateFile)))
		}},
		{"corrupt public", func(t *testing.T, dir string, _ *config.Config) {
			must(t, os.WriteFile(filepath.Join(dir, "ssh", PublicFile), []byte("broken"), 0644))
		}},
		{"public private mode", func(t *testing.T, dir string, _ *config.Config) {
			must(t, os.Chmod(filepath.Join(dir, "ssh", PrivateFile), 0644))
		}},
		{"symlink", func(t *testing.T, dir string, _ *config.Config) {
			p := filepath.Join(dir, "ssh", PublicFile)
			must(t, os.Rename(p, p+".saved"))
			must(t, os.Symlink(p+".saved", p))
		}},
		{"changed grant", func(_ *testing.T, _ string, cfg *config.Config) { cfg.Containers[0].Name = "different" }},
		{"changed algorithm", func(_ *testing.T, _ string, cfg *config.Config) { cfg.AttestedKeys[0].Key = config.KeyEd25519 }},
		{"changed owner", func(_ *testing.T, _ string, cfg *config.Config) { cfg.AttestedKeys[0].UID++ }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			cfg := testConfig()
			dir := filepath.Join(t.TempDir(), "keys")
			_, err := Ensure(dir, cfg)
			must(t, err)
			original, err := os.ReadFile(filepath.Join(dir, "vpn", PrivateFile))
			must(t, err)
			mutate.apply(t, dir, cfg)
			if _, err := Ensure(dir, cfg); err == nil {
				t.Fatal("corrupt or mismatched store accepted by boot")
			}
			_, publicErr := LoadPublic(dir, cfg)
			switch mutate.name {
			case "missing private", "corrupt public", "public private mode", "symlink":
				// Only boot enters the workload-owned directories. Shim consumes
				// the already committed public inventory, not mutable key files.
				must(t, publicErr)
			default:
				if publicErr == nil {
					t.Fatal("corrupt or mismatched inventory accepted by shim")
				}
			}
			after, err := os.ReadFile(filepath.Join(dir, "vpn", PrivateFile))
			must(t, err)
			if !bytes.Equal(after, original) {
				t.Fatal("failed retry rotated an unaffected key")
			}
		})
	}
}

func TestPublicInventoryWithWorkloadOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to exercise a different measured owner and drop DAC capabilities")
	}
	cfg := testConfig()
	for i := range cfg.AttestedKeys {
		cfg.AttestedKeys[i].UID, cfg.AttestedKeys[i].GID = 1000, 1000
	}
	if dir := os.Getenv("TINFOIL_ATTESTED_KEY_STORE"); dir != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// Match the shim's lack of DAC override/read-search. Do this only in
		// the dedicated subprocess, never in the parent test runner.
		caps := [2]unix.CapUserData{}
		must(t, unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &caps[0]))
		if _, err := os.ReadFile(filepath.Join(dir, "ssh", PublicFile)); !os.IsPermission(err) {
			t.Fatalf("test did not deny traversal of workload-owned directory: %v", err)
		}
		items, err := LoadPublic(dir, cfg)
		must(t, err)
		if len(items) != 3 {
			t.Fatal("public inventory omitted workload-owned keys")
		}
		return
	}
	dir := filepath.Join(t.TempDir(), "keys")
	_, err := Ensure(dir, cfg)
	must(t, err)
	child := exec.Command(os.Args[0], "-test.run=^TestPublicInventoryWithWorkloadOwner$")
	child.Env = append(os.Environ(), "TINFOIL_ATTESTED_KEY_STORE="+dir)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("restricted shim public handoff: %v\n%s", err, output)
	}
}

func TestPrivateKeyMismatchFailsBoot(t *testing.T) {
	cfg := testConfig()
	dir := filepath.Join(t.TempDir(), "keys")
	_, err := Ensure(dir, cfg)
	must(t, err)
	other := filepath.Join(t.TempDir(), "keys")
	_, err = Ensure(other, cfg)
	must(t, err)
	data, err := os.ReadFile(filepath.Join(other, "ssh", PrivateFile))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "ssh", PrivateFile), data, 0600))
	if _, err := Ensure(dir, cfg); err == nil {
		t.Fatal("mismatched private key accepted")
	}
}

func TestConcurrentBootRetriesPublishOneInventory(t *testing.T) {
	cfg := testConfig()
	dir := filepath.Join(t.TempDir(), "keys")
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if _, err := Ensure(dir, cfg); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	_, err := LoadPublic(dir, cfg)
	must(t, err)
	entries, err := os.ReadDir(filepath.Dir(dir))
	must(t, err)
	if len(entries) != 1 {
		t.Fatalf("staging keys leaked: %v", entries)
	}
}

func TestEmptyAndMissingInventories(t *testing.T) {
	cfg := &config.Config{}
	dir := filepath.Join(t.TempDir(), "keys")
	if _, err := LoadPublic(dir, cfg); err == nil {
		t.Fatal("missing inventory accepted")
	}
	items, err := Ensure(dir, cfg)
	must(t, err)
	if len(items) != 0 {
		t.Fatal("empty config generated keys")
	}
	_, err = LoadPublic(dir, cfg)
	must(t, err)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
