package volume

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyTableKeyMatchesExistingVolumes(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	// HKDF-SHA256 with the original empty salt and table-key context.
	const want = "20b0c8dd8a843102f162baa2fd868ac68c493ad5ef4bf1fa11005771a50b107deb62" +
		"be3df93221513dfa1304bc10b4eadefb58b28306be3502dfd09c7a37ddfaa063aa" +
		"0bb12ca32b513c2a8328d907116517faf8783820752efe780f990b42d1"
	w := new(volume)
	got, reserved, err := w.tableKey(key, false, VersionHKDF)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want || reserved != 0 {
		t.Fatalf("legacy mapping changed: key = %x, reserved = %d", got, reserved)
	}
}

func TestLegacyInitializeDoesNotModifyDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "volume")
	want := bytes.Repeat([]byte{0xa5}, blankProbeSize)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	w := &volume{source: source}
	if err := w.activate(t.Context(), make([]byte, 64), true, VersionHKDF); err == nil || !strings.Contains(err.Error(), "can only be unlocked") {
		t.Fatalf("legacy initialize = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("rejected legacy initialization modified the disk")
	}
}

func TestLegacyRequestsRejectCreationAndNonLegacyKeySizes(t *testing.T) {
	for _, test := range []struct {
		name    string
		op      byte
		keySize int
	}{
		{"initialize", opInitialize, 64},
		{"minimum Argon2 key", opUnlock, MinKeyBytes},
		{"short key", opUnlock, 63},
		{"long key", opUnlock, 65},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := append([]byte{VersionHKDF, test.op}, make([]byte, test.keySize)...)
			// Rejection must happen before any access to the absent devices.
			w := new(volume)
			status, err := w.handle(t.Context(), packet)
			if status != statusRejected || err == nil {
				t.Fatalf("request = %q, %v; want rejected", status, err)
			}
		})
	}
}
