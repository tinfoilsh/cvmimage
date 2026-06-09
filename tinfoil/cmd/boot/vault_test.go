package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// TestVaultFetchOpenLive exercises the cmd/boot fetch + circl-open path against
// a running --dev-verify vault. Gated on VAULT_TEST_URL (a secret named API_KEY
// must already be stored under VAULT_TEST_REPO), so the normal suite stays
// offline.
func TestVaultFetchOpenLive(t *testing.T) {
	url := os.Getenv("VAULT_TEST_URL")
	if url == "" {
		t.Skip("set VAULT_TEST_URL to run against a live --dev-verify vault")
	}
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	req := vaultFetchRequest{
		Repo:       os.Getenv("VAULT_TEST_REPO"),
		SecretRefs: []string{"API_KEY"},
		Nonce:      strconv.FormatInt(time.Now().UnixNano(), 10),
		PKW:        hex.EncodeToString(id.MarshalPublicKey()),
	}
	resp, err := vaultFetch(url, req)
	if err != nil {
		t.Fatalf("vaultFetch: %v", err)
	}
	plain, err := vaultOpen(id, resp.Enc, resp.Ciphertext)
	if err != nil {
		t.Fatalf("vaultOpen: %v", err)
	}
	var secrets map[string]string
	if err := json.Unmarshal(plain, &secrets); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if want := os.Getenv("VAULT_TEST_VALUE"); secrets["API_KEY"] != want {
		t.Fatalf("API_KEY = %q, want %q", secrets["API_KEY"], want)
	}
	t.Logf("cmd/boot fetched + decrypted via real vault: %v", secrets)
}
