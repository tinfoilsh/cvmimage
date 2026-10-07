package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	systemRAM = "System RAM"
	reserved  = "Reserved"
	acpi      = "ACPI Tables"
)

type memmapSpan struct {
	start, end uint64
	kind       string
}

// fakeMemmapRoot lays out a sysfs firmware memory map from [start, end) spans,
// which it writes back with the inclusive ends sysfs uses.
func fakeMemmapRoot(t *testing.T, spans []memmapSpan) string {
	t.Helper()
	root := t.TempDir()
	for index, span := range spans {
		dir := filepath.Join(root, fmt.Sprintf("%d", index))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{
			"start": fmt.Sprintf("%#x\n", span.start),
			"end":   fmt.Sprintf("%#x\n", span.end-1),
			"type":  span.kind + "\n",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

const (
	oneMiB   = 1 << 20
	twoGiB   = 2 << 30
	fourGiB  = 4 << 30
	oneTiB   = 1024 << 30
	htBase   = 1012 << 30
	lowSplit = 0xb000_0000
)

// The pages an SEV-SNP image reserves below 2 MiB, as its guests report them.
var imageSpans = []memmapSpan{
	{0x7000, 0x8000, reserved},
	{0x2_0000, 0x2_1000, reserved},
	{0xe_0000, 0xe_1000, acpi},
	{0xe_1000, 0xe_3000, reserved},
	{0xf_0000, 0xf_2000, reserved},
	{0x10_0000, 0x10_6000, reserved},
	{0x10_7000, 0x11_8000, reserved},
	{0x12_0000, 0x15_0000, reserved},
}

// guestMap is the map a guest given ram reports: the image's pages carved out
// of low RAM, which QEMU restacks above 4 GiB once the guest outgrows the
// 32-bit aperture.
func guestMap(ram uint64) []memmapSpan {
	low := ram
	if ram >= lowSplit {
		low = twoGiB
	}
	var spans []memmapSpan
	at := uint64(0)
	for _, image := range imageSpans {
		if image.start > at {
			spans = append(spans, memmapSpan{at, image.start, systemRAM})
		}
		spans = append(spans, image)
		at = image.end
	}
	spans = append(spans, memmapSpan{at, low, systemRAM})
	if ram > low {
		spans = append(spans, memmapSpan{fourGiB, fourGiB + ram - low, systemRAM})
	}
	return spans
}

func TestEnforceRAMSizeAcceptsTheConfiguredSize(t *testing.T) {
	for _, ram := range []uint64{1 << 30, twoGiB, fourGiB, 64 << 30} {
		detail, err := enforceRAMSize(fakeMemmapRoot(t, guestMap(ram)), int(ram/oneMiB))
		if err != nil {
			t.Fatalf("%d MiB: %v", ram/oneMiB, err)
		}
		if want := fmt.Sprintf("%d MiB of RAM", ram/oneMiB); detail != want {
			t.Fatalf("detail %q, want %q", detail, want)
		}
	}
}

// The TDX reset page is reserved, so it neither helps nor hurts.
func TestEnforceRAMSizeIgnoresTheResetPage(t *testing.T) {
	const eightGiB = 8 << 30
	spans := append(guestMap(eightGiB), memmapSpan{0xffff_f000, fourGiB, reserved})
	if _, err := enforceRAMSize(fakeMemmapRoot(t, spans), eightGiB/oneMiB); err != nil {
		t.Fatalf("enforceRAMSize: %v", err)
	}
}

func TestEnforceRAMSizeRejectsAShortLaunch(t *testing.T) {
	if _, err := enforceRAMSize(fakeMemmapRoot(t, guestMap(fourGiB)), 65536); err == nil {
		t.Fatal("a launch providing 4 GiB was accepted for a 64 GiB config")
	}
}

// The shim validates none of what the host marks reserved, so a host cannot
// pass a reserved range off as the RAM a config asked for.
func TestEnforceRAMSizeRejectsReservedRangesPassedOffAsRAM(t *testing.T) {
	root := fakeMemmapRoot(t, []memmapSpan{
		{0, 1 << 30, systemRAM},
		{1 << 30, 64 << 30, reserved},
		{64 << 30, 64<<30 + 0x1000, systemRAM},
	})
	if _, err := enforceRAMSize(root, 65536); err == nil {
		t.Fatal("a launch providing 1 GiB of RAM was accepted for a 64 GiB config")
	}
}

// The allowance covers the image's own pages and nothing more; 2 MiB is the
// bound compiler/src/image.rs holds the layout to.
func TestEnforceRAMSizeAllowsOnlyTheImagesOwnPages(t *testing.T) {
	const ram = fourGiB
	if imageReservedBytes != 2<<20 {
		t.Fatalf("allowance %#x, the compiler checks 2 MiB", imageReservedBytes)
	}
	at := func(given uint64) error {
		spans := []memmapSpan{{0, given, systemRAM}}
		_, err := enforceRAMSize(fakeMemmapRoot(t, spans), ram/oneMiB)
		return err
	}
	if err := at(ram - imageReservedBytes); err != nil {
		t.Fatalf("a launch short by the allowance was refused: %v", err)
	}
	if err := at(ram - imageReservedBytes - 0x1000); err == nil {
		t.Fatal("a launch short by more than the allowance was accepted")
	}
}

// QEMU reserves the HyperTransport hole for an AMD vCPU and restacks the high
// bank above 1 TiB, which puts the reserved entry below the top of RAM.
func TestEnforceRAMSizeToleratesTheHyperTransportHole(t *testing.T) {
	const ram = oneTiB
	spans := append(guestMap(twoGiB),
		memmapSpan{htBase, oneTiB, reserved},
		memmapSpan{oneTiB, oneTiB + ram - twoGiB, systemRAM},
	)
	if _, err := enforceRAMSize(fakeMemmapRoot(t, spans), ram/oneMiB); err != nil {
		t.Fatalf("enforceRAMSize: %v", err)
	}
}

func TestEnforceRAMSizeRejectsAnUnusableMap(t *testing.T) {
	if _, err := enforceRAMSize(fakeMemmapRoot(t, nil), 4096); err == nil {
		t.Fatal("an empty map was accepted")
	}
	if _, err := enforceRAMSize(filepath.Join(t.TempDir(), "absent"), 4096); err == nil {
		t.Fatal("a missing map was accepted")
	}
	// Entry 0 is System RAM, so every field of it is read.
	for _, name := range []string{"end", "type"} {
		root := fakeMemmapRoot(t, guestMap(fourGiB))
		if err := os.Remove(filepath.Join(root, "0", name)); err != nil {
			t.Fatal(err)
		}
		if _, err := enforceRAMSize(root, 4096); err == nil {
			t.Fatalf("an entry without %s was accepted", name)
		}
	}
	root := fakeMemmapRoot(t, guestMap(fourGiB))
	if err := os.WriteFile(filepath.Join(root, "0", "end"), []byte("nonsense\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := enforceRAMSize(root, 4096); err == nil {
		t.Fatal("an unparsable entry was accepted")
	}
}

func TestEnforceRAMSizeRejectsAnEmptyConfig(t *testing.T) {
	if _, err := enforceRAMSize(fakeMemmapRoot(t, guestMap(fourGiB)), 0); err == nil {
		t.Fatal("a config asking for no RAM was accepted")
	}
}
