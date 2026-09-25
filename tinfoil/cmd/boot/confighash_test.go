package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxlabi "github.com/google/go-tdx-guest/client/linuxabi"
)

// The Intel TDX module ABI puts TDINFO_STRUCT at byte 512 of the 1024-byte
// TDREPORT_STRUCT and MRCONFIGID at byte 64 within it. The code derives both
// from field sizes; this pins the result to the spec's own numbers.
func TestMRCONFIGIDSitsWhereTheTDXABISaysItDoes(t *testing.T) {
	if tdInfoOffset != 512 {
		t.Fatalf("TDINFO_STRUCT at %d, spec says 512", tdInfoOffset)
	}
	if mrConfigIDOffset != 576 {
		t.Fatalf("MRCONFIGID at %d, spec says 576", mrConfigIDOffset)
	}
	if mrConfigIDOffset+tdxabi.MrConfigIDSize > tdxlabi.TdReportSize {
		t.Fatalf("MRCONFIGID runs past the %d-byte TD report", tdxlabi.TdReportSize)
	}
}

func TestConfigHashFromMRCONFIGIDTakesTheZeroPaddedHash(t *testing.T) {
	want := sha256.Sum256([]byte("tinfoil-config.yml"))
	field := make([]byte, tdxabi.MrConfigIDSize)
	copy(field, want[:])

	got, err := configHashFromMRCONFIGID(field)
	if err != nil {
		t.Fatalf("configHashFromMRCONFIGID: %v", err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	if !hexHashPattern.MatchString(got) {
		t.Fatalf("hash %q is not the form loadAndVerifyConfig accepts", got)
	}
}

// A host that can set the padding to anything sets a field the guest reports
// as checked. Rejecting it keeps MRCONFIGID to the one encoding.
func TestConfigHashFromMRCONFIGIDRejectsANonzeroTail(t *testing.T) {
	for _, index := range []int{sha256.Size, tdxabi.MrConfigIDSize - 1} {
		field := make([]byte, tdxabi.MrConfigIDSize)
		field[index] = 1
		if _, err := configHashFromMRCONFIGID(field); err == nil {
			t.Fatalf("byte %d nonzero was accepted", index)
		} else if !strings.Contains(err.Error(), "not zeros") {
			t.Fatalf("byte %d: %v", index, err)
		}
	}
}

func TestConfigHashFromMRCONFIGIDRejectsTheWrongLength(t *testing.T) {
	for _, size := range []int{0, sha256.Size, tdxabi.MrConfigIDSize - 1, tdxabi.MrConfigIDSize + 1} {
		if _, err := configHashFromMRCONFIGID(make([]byte, size)); err == nil {
			t.Fatalf("%d bytes was accepted as MRCONFIGID", size)
		}
	}
}
