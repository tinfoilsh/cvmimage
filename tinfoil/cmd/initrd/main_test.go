package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPinnedVeritySaltMatchesRepartSeed(t *testing.T) {
	seedBytes, err := hex.DecodeString(strings.ReplaceAll(repartSeed, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, seedBytes)
	if _, err := mac.Write([]byte("verity-salt")); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mac.Sum(nil)); got != veritySalt {
		t.Fatalf("derived salt = %s, want %s", got, veritySalt)
	}

	mkosiConfig, err := os.ReadFile("../../../mkosi.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mkosiConfig), "Seed="+repartSeed+"\n") {
		t.Fatalf("mkosi.conf does not pin repart seed %s", repartSeed)
	}

	repartConfig, err := os.ReadFile("../../../mkosi.repart/11-root-verity.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{
		"VerityDataBlockSizeBytes=4096\n",
		"VerityHashBlockSizeBytes=4096\n",
	} {
		if !strings.Contains(string(repartConfig), setting) {
			t.Fatalf("root verity repart config is missing %s", strings.TrimSpace(setting))
		}
	}
}

func TestVerityTableParamsAreFullyPinned(t *testing.T) {
	roothash := strings.Repeat("ab", 32)
	got := verityTableParams("8:1", "8:2", 786432, roothash)
	want := "1 8:1 8:2 4096 4096 786432 1 sha256 " + roothash + " " + veritySalt
	if got != want {
		t.Fatalf("verityTableParams() = %q, want %q", got, want)
	}
}

func TestIsHex64(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if !isHex64(valid) {
		t.Fatal("valid roothash rejected")
	}
	for _, value := range []string{
		valid[:63],
		valid + "0",
		"0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdez",
	} {
		if isHex64(value) {
			t.Fatalf("invalid roothash accepted: %q", value)
		}
	}
}

func TestSplitRoothashAndGUID(t *testing.T) {
	roothash := "0123456789abcdef0123456789abcdefabcDEF0123456789ABCDef0123456789"
	root, verity := splitRoothash(roothash)
	if root != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("root half = %q", root)
	}
	if verity != "abcDEF0123456789ABCDef0123456789" {
		t.Fatalf("verity half = %q", verity)
	}
	if got := guidFromHex32(root); got != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Fatalf("root GUID = %q", got)
	}
	if got := guidFromHex32(verity); got != "abcdef01-2345-6789-abcd-ef0123456789" {
		t.Fatalf("verity GUID = %q", got)
	}
}

func TestCmdlineValueFromRejectsAmbiguity(t *testing.T) {
	value, err := cmdlineValueFrom("console=hvc0 roothash=abcd", "roothash")
	if err != nil || value != "abcd" {
		t.Fatalf("cmdlineValueFrom() = %q, %v", value, err)
	}
	if _, err := cmdlineValueFrom("roothash=one roothash=two", "roothash"); err == nil {
		t.Fatal("duplicate roothash accepted")
	}
	if _, err := cmdlineValueFrom("console=hvc0", "roothash"); !os.IsNotExist(err) {
		t.Fatalf("missing roothash error = %v, want os.ErrNotExist", err)
	}
}

func withSysClassBlock(t *testing.T, root string) {
	t.Helper()
	old := sysClassBlock
	sysClassBlock = root
	t.Cleanup(func() { sysClassBlock = old })
}

func TestVerityDataBlocksUsesKernelGeometry(t *testing.T) {
	root := t.TempDir()
	sizeDir := filepath.Join(root, "sdb1")
	if err := os.MkdirAll(sizeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sizeDir, "size"), []byte("6291456\n"), 0644); err != nil {
		t.Fatal(err)
	}
	withSysClassBlock(t, root)

	got, err := verityDataBlocks("/dev/sdb1")
	if err != nil {
		t.Fatal(err)
	}
	if got != 786432 {
		t.Fatalf("verityDataBlocks() = %d, want 786432", got)
	}

	if err := os.WriteFile(filepath.Join(sizeDir, "size"), []byte("6291455\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := verityDataBlocks("/dev/sdb1"); err == nil {
		t.Fatal("misaligned partition size accepted")
	}

	maxAlignedSectors := ^uint64(0) - 7
	if err := os.WriteFile(
		filepath.Join(sizeDir, "size"),
		[]byte(strconv.FormatUint(maxAlignedSectors, 10)),
		0644,
	); err != nil {
		t.Fatal(err)
	}
	got, err = verityDataBlocks("/dev/sdb1")
	if err != nil {
		t.Fatalf("maximum aligned sector count rejected: %v", err)
	}
	if want := maxAlignedSectors / 8; got != want {
		t.Fatalf("maximum data block count = %d, want %d", got, want)
	}
}

func TestBlockDevNumberValidatesSysfs(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "sdb1")
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatal(err)
	}
	withSysClassBlock(t, root)

	path := filepath.Join(devDir, "dev")
	if err := os.WriteFile(path, []byte("8:17\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := blockDevNumber("/dev/sdb1"); err != nil || got != "8:17" {
		t.Fatalf("blockDevNumber() = %q, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("8:17:1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := blockDevNumber("/dev/sdb1"); err == nil {
		t.Fatal("malformed device number accepted")
	}
}
