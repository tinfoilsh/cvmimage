package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateReusesPrivateHPKEIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hpke.json")
	first, err := Generate("cvm.example", false, path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate("cvm.example", false, path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.HPKEKeyBytes, second.HPKEKeyBytes) || first.Body().HPKEKey != second.Body().HPKEKey {
		t.Fatal("HPKE identity changed")
	}
	if first.Body().TLSKeyFP == second.Body().TLSKeyFP {
		t.Fatal("TLS identity was not regenerated")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("HPKE identity is not private")
	}
}

func TestGenerateRequiresDomainOutsideDummyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hpke.json")
	if _, err := Generate("", false, path); err == nil {
		t.Fatal("missing domain accepted")
	}
	node, err := Generate("", true, path)
	if err != nil || node.Domain != "localhost" {
		t.Fatalf("dummy identity: %v", err)
	}
}
