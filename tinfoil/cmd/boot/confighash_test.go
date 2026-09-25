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

// The Intel TDX module ABI puts TDINFO_STRUCT at byte 512 of the 1024-byte
// TDREPORT_STRUCT and MRCONFIGID at byte 64 within it. The constants are
// built from field widths, so pin the arithmetic to the spec's own numbers.
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
	if tdxabi.MrConfigIDSize < sha256.Size {
		t.Fatalf("MRCONFIGID is %d bytes, too small for a SHA-256", tdxabi.MrConfigIDSize)
	}
}

// tdReport fills a TD report with a distinct byte per measurement register, so
// a cut at the wrong offset returns someone else's register rather than
// something that merely fails to parse.
func tdReport(t *testing.T, mrConfigID []byte) []byte {
	t.Helper()
	report := make([]byte, tdxlabi.TdReportSize)
	mrTDOffset := tdInfoOffset + tdxabi.TdAttributesSize + tdxabi.XfamSize
	for _, register := range []struct {
		offset int
		fill   byte
	}{
		{tdInfoOffset, 0xa1}, // ATTRIBUTES and XFAM
		{mrTDOffset, 0xa2},   // MRTD
		{mrConfigIDOffset + tdxabi.MrConfigIDSize, 0xa3}, // MROWNER onwards
	} {
		for i := register.offset; i < len(report); i++ {
			report[i] = register.fill
		}
	}
	copy(report[mrConfigIDOffset:], mrConfigID)
	return report
}

func TestConfigHashFromTDReportCutsMRCONFIGIDAndNotItsNeighbours(t *testing.T) {
	want := sha256.Sum256([]byte("tinfoil-config.yml"))
	field := make([]byte, tdxabi.MrConfigIDSize)
	copy(field, want[:])

	got, err := configHashFromTDReport(tdReport(t, field))
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
		report := tdReport(t, field)
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
