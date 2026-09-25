package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxlabi "github.com/google/go-tdx-guest/client/linuxabi"
)

// Offsets the Intel TDX module ABI states for a 1024-byte TDREPORT_STRUCT.
// Written out rather than derived, so they pin the constants the code builds
// from its field widths instead of restating them.
const (
	specTDInfoOffset     = 512
	specMRTDOffset       = 528
	specMRCONFIGIDOffset = 576
	specMROWNEROffset    = 624
)

func TestMRCONFIGIDSitsWhereTheTDXABISaysItDoes(t *testing.T) {
	if tdInfoOffset != specTDInfoOffset {
		t.Fatalf("TDINFO_STRUCT at %d, spec says %d", tdInfoOffset, specTDInfoOffset)
	}
	if mrConfigIDOffset != specMRCONFIGIDOffset {
		t.Fatalf("MRCONFIGID at %d, spec says %d", mrConfigIDOffset, specMRCONFIGIDOffset)
	}
	if mrConfigIDOffset+tdxabi.MrConfigIDSize > tdxlabi.TdReportSize {
		t.Fatalf("MRCONFIGID runs past the %d-byte TD report", tdxlabi.TdReportSize)
	}
	if tdxabi.MrConfigIDSize < sha256.Size {
		t.Fatalf("MRCONFIGID is %d bytes, too small for a SHA-256", tdxabi.MrConfigIDSize)
	}
}

// tdReport paints every byte of a TD report, one value per region, so that a
// cut at any wrong offset comes back as a region's fill rather than as
// anything a caller could mistake for a config hash.
func tdReport(mrConfigID []byte) []byte {
	report := make([]byte, tdxlabi.TdReportSize)
	for _, region := range []struct {
		from, to int
		fill     byte
	}{
		{0, specTDInfoOffset, 0xa0},                  // REPORTMACSTRUCT and TEE_TCB_INFO
		{specTDInfoOffset, specMRTDOffset, 0xa1},     // ATTRIBUTES and XFAM
		{specMRTDOffset, specMRCONFIGIDOffset, 0xa2}, // MRTD
		{specMROWNEROffset, len(report), 0xa3},       // MROWNER onwards
	} {
		for i := region.from; i < region.to; i++ {
			report[i] = region.fill
		}
	}
	copy(report[specMRCONFIGIDOffset:specMROWNEROffset], mrConfigID)
	return report
}

func TestConfigHashFromTDReportCutsMRCONFIGIDAndNotItsNeighbours(t *testing.T) {
	want := sha256.Sum256([]byte("tinfoil-config.yml"))
	field := make([]byte, tdxabi.MrConfigIDSize)
	copy(field, want[:])

	got, err := configHashFromTDReport(tdReport(field))
	if err != nil {
		t.Fatalf("configHashFromTDReport: %v", err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	if !hexHashPattern.MatchString(got) {
		t.Fatalf("hash %q is not the form loadAndVerifyConfig accepts", got)
	}
}

// A report that is not the size the ioctl returns has not been laid out the
// way the offsets assume, so no offset in it can be trusted.
func TestConfigHashFromTDReportRejectsTheWrongSize(t *testing.T) {
	field := make([]byte, tdxabi.MrConfigIDSize)
	for _, size := range []int{0, tdxlabi.TdReportSize - 1, tdxlabi.TdReportSize + 1} {
		report := tdReport(field)
		if len(report) > size {
			report = report[:size]
		} else {
			report = append(report, bytes.Repeat([]byte{0}, size-len(report))...)
		}
		if _, err := configHashFromTDReport(report); err == nil {
			t.Fatalf("%d bytes was accepted as a TD report", size)
		}
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
}

// A host that can set the padding to anything sets a field the verifier pins
// whole. Rejecting it keeps MRCONFIGID to the one encoding.
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
