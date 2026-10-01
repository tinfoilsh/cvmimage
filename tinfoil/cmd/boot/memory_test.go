package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakeMemmapRoot lays out a sysfs firmware memory map from [start, end) spans,
// which it writes back with the inclusive ends sysfs uses.
func fakeMemmapRoot(t *testing.T, spans [][2]uint64) string {
	t.Helper()
	root := t.TempDir()
	for index, span := range spans {
		dir := filepath.Join(root, fmt.Sprintf("%d", index))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]uint64{"start": span[0], "end": span[1] - 1} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, fmt.Appendf(nil, "%#x\n", value), 0o644); err != nil {
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
	shimSpan = 0x20000
)

// A 4 GiB SNP guest: low RAM to 2 GiB, the aperture absent from the map, and
// the rest restacked above 4 GiB.
func snpSpans() [][2]uint64 {
	return [][2]uint64{
		{0, shimSpan},
		{shimSpan, twoGiB},
		{fourGiB, fourGiB + twoGiB},
	}
}

func TestEnforceRAMSizeAcceptsTheConfiguredSize(t *testing.T) {
	root := fakeMemmapRoot(t, snpSpans())
	detail, err := enforceRAMSize(root, 4096)
	if err != nil {
		t.Fatalf("enforceRAMSize: %v", err)
	}
	if detail != "4096 MiB of RAM" {
		t.Fatalf("detail %q", detail)
	}
}

// The reset page has an E820 entry on TDX and is not RAM the host provided.
func TestEnforceRAMSizeIgnoresTheResetPage(t *testing.T) {
	spans := append(snpSpans(), [2]uint64{resetPageBase(), fourGiB})
	root := fakeMemmapRoot(t, spans)
	if _, err := enforceRAMSize(root, 4096); err != nil {
		t.Fatalf("enforceRAMSize: %v", err)
	}
}

// Nothing stops the reset page being coalesced with the high RAM above it.
func TestEnforceRAMSizeIgnoresACoalescedResetPage(t *testing.T) {
	root := fakeMemmapRoot(t, [][2]uint64{
		{0, shimSpan},
		{shimSpan, twoGiB},
		{resetPageBase(), fourGiB + twoGiB},
	})
	if _, err := enforceRAMSize(root, 4096); err != nil {
		t.Fatalf("enforceRAMSize: %v", err)
	}
}

// A guest small enough that QEMU never restacks above 4 GiB.
func TestEnforceRAMSizeAcceptsAnUnsplitGuest(t *testing.T) {
	root := fakeMemmapRoot(t, [][2]uint64{{0, shimSpan}, {shimSpan, twoGiB}})
	if _, err := enforceRAMSize(root, 2048); err != nil {
		t.Fatalf("enforceRAMSize: %v", err)
	}
}

func TestEnforceRAMSizeRejectsAShortLaunch(t *testing.T) {
	root := fakeMemmapRoot(t, snpSpans())
	if _, err := enforceRAMSize(root, 65536); err == nil {
		t.Fatal("a launch providing 4 GiB was accepted for a 64 GiB config")
	}
}

func TestEnforceRAMSizeRejectsALongLaunch(t *testing.T) {
	root := fakeMemmapRoot(t, snpSpans())
	if _, err := enforceRAMSize(root, 2048); err == nil {
		t.Fatal("a launch providing 4 GiB was accepted for a 2 GiB config")
	}
}

func TestEnforceRAMSizeRejectsAnUnusableMap(t *testing.T) {
	for name, spans := range map[string][][2]uint64{
		"empty": {},
	} {
		if _, err := enforceRAMSize(fakeMemmapRoot(t, spans), 4096); err == nil {
			t.Fatalf("%s map was accepted", name)
		}
	}
	if _, err := enforceRAMSize(filepath.Join(t.TempDir(), "absent"), 4096); err == nil {
		t.Fatal("a missing map was accepted")
	}
	root := fakeMemmapRoot(t, snpSpans())
	if err := os.WriteFile(filepath.Join(root, "0", "end"), []byte("nonsense\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := enforceRAMSize(root, 4096); err == nil {
		t.Fatal("an unparsable entry was accepted")
	}
}

func TestEnforceRAMSizeRejectsAnEmptyConfig(t *testing.T) {
	root := fakeMemmapRoot(t, snpSpans())
	if _, err := enforceRAMSize(root, 0); err == nil {
		t.Fatal("a config asking for no RAM was accepted")
	}
}

func resetPageBase() uint64 { return notGuestRAM[0][0] }

// QEMU reserves the HyperTransport hole for an AMD vCPU and restacks the high
// bank above 1 TiB, which puts the reserved entry below the top of RAM.
func TestEnforceRAMSizeIgnoresTheHyperTransportHole(t *testing.T) {
	const ram = 1024 * 1024 * oneMiB // 1 TiB
	root := fakeMemmapRoot(t, [][2]uint64{
		{0, shimSpan},
		{shimSpan, twoGiB},
		{htBase, oneTiB},
		{oneTiB, oneTiB + ram - twoGiB},
	})
	if _, err := enforceRAMSize(root, ram/oneMiB); err != nil {
		t.Fatalf("enforceRAMSize: %v", err)
	}
}
