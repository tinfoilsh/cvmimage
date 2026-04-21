package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func buildSPDMReport(tlvs []tlvEntry) []byte {
	var opaque []byte
	for _, t := range tlvs {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:2], t.typ)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(t.val)))
		opaque = append(opaque, hdr...)
		opaque = append(opaque, t.val...)
	}
	var buf []byte
	buf = append(buf, make([]byte, spdmRequestLen)...)
	buf = append(buf, make([]byte, 5)...)
	buf = append(buf, 0, 0, 0)
	buf = append(buf, make([]byte, spdmNonceLen)...)
	ol := make([]byte, 2)
	binary.LittleEndian.PutUint16(ol, uint16(len(opaque)))
	buf = append(buf, ol...)
	buf = append(buf, opaque...)
	buf = append(buf, make([]byte, 64)...)
	return buf
}

type tlvEntry struct {
	typ uint16
	val []byte
}

// All PDI constants below are copied verbatim from the Python reference:
// nvtrust/guest_tools/ppcie-verifier-sdk-cpp/tests/test_validate_topology.py
//
// Python prints printable ASCII in byte literals (@ = 0x40, H = 0x48, etc.)
// so the Go hex values here are the direct byte-for-byte equivalents.

// test_gpu_topology_check line 34 — switch PDIs reported by each GPU:
//
//	b'@\xb9\xc6\xb3\xd7H\xfd\x90'
//	b'\xfd\xb5)\xf1G<\xb2%'
//	b'\x10C\xc1N\x83Y\x96c'
//	b'\xd0\xf6\x9d\x02\x8e\x15\n\xaa'
var (
	// b'@\xb9\xc6\xb3\xd7H\xfd\x90'  →  @ = 0x40, H = 0x48
	switchA = []byte{0x40, 0xb9, 0xc6, 0xb3, 0xd7, 0x48, 0xfd, 0x90}
	// b'\xfd\xb5)\xf1G<\xb2%'  →  ) = 0x29, G = 0x47, < = 0x3c, % = 0x25
	switchB = []byte{0xfd, 0xb5, 0x29, 0xf1, 0x47, 0x3c, 0xb2, 0x25}
	// b'\x10C\xc1N\x83Y\x96c'  →  C = 0x43, N = 0x4e, Y = 0x59, c = 0x63
	switchC = []byte{0x10, 0x43, 0xc1, 0x4e, 0x83, 0x59, 0x96, 0x63}
	// b'\xd0\xf6\x9d\x02\x8e\x15\n\xaa'  →  \n = 0x0a
	switchD = []byte{0xd0, 0xf6, 0x9d, 0x02, 0x8e, 0x15, 0x0a, 0xaa}
)

// Switch device PDIs as stored in switch attestation reports (field 22).
// These are byte-reversed relative to the GPU-reported switch PDIs above,
// matching the Python reference test's get_data_side_effect for OPAQUE_FIELD_ID_DEVICE_PDI.
var (
	switchDevA = []byte{0x90, 0xfd, 0x48, 0xd7, 0xb3, 0xc6, 0xb9, 0x40}
	switchDevB = []byte{0x25, 0xb2, 0x3c, 0x47, 0xf1, 0x29, 0xb5, 0xfd}
	switchDevC = []byte{0x63, 0x96, 0x59, 0x83, 0x4e, 0xc1, 0x43, 0x10}
	switchDevD = []byte{0xaa, 0x0a, 0x15, 0x8e, 0x02, 0x9d, 0xf6, 0xd0}
)

// OPAQUE_FIELD_ID_SWITCH_GPU_PDIS (line 48-49):
//
//	b'@\xb9\xc6\xb3\xd7H\xfd\x90'
//	b'\xfd\xb5)\xf1G<\xb2%'
//	b"\xbf\\\xc6'\xc8\x13\xae\xd8"   →  \\ = 0x5c, ' = 0x27
//	b'\xe2\xd8[Y\x0eq2\x98'           →  [ = 0x5b, Y = 0x59, q = 0x71, 2 = 0x32
//	b'\x10C\xc1N\x83Y\x96c'
//	b'1d\x9c\xf1\x1c\x82\x08X'       →  1 = 0x31, d = 0x64, X = 0x58
//	b'\xd0\xf6\x9d\x02\x8e\x15\n\xaa'
//	b'\xd0\xf6\x9d\x02\x8e\x15\n\xab'
var (
	gpuPDI0 = []byte{0x40, 0xb9, 0xc6, 0xb3, 0xd7, 0x48, 0xfd, 0x90}
	gpuPDI1 = []byte{0xfd, 0xb5, 0x29, 0xf1, 0x47, 0x3c, 0xb2, 0x25}
	gpuPDI2 = []byte{0xbf, 0x5c, 0xc6, 0x27, 0xc8, 0x13, 0xae, 0xd8}
	gpuPDI3 = []byte{0xe2, 0xd8, 0x5b, 0x59, 0x0e, 0x71, 0x32, 0x98}
	gpuPDI4 = []byte{0x10, 0x43, 0xc1, 0x4e, 0x83, 0x59, 0x96, 0x63}
	gpuPDI5 = []byte{0x31, 0x64, 0x9c, 0xf1, 0x1c, 0x82, 0x08, 0x58}
	gpuPDI6 = []byte{0xd0, 0xf6, 0x9d, 0x02, 0x8e, 0x15, 0x0a, 0xaa}
	gpuPDI7 = []byte{0xd0, 0xf6, 0x9d, 0x02, 0x8e, 0x15, 0x0a, 0xab}
)

// test_gpu_topology_check line 43 — expected unique_switches after LE read:
//
//	{'639659834ec14310', '90fd48d7b3c6b940', 'aa0a158e029df6d0', '25b23c47f129b5fd'}
//
// Like the Python reference, our Go code applies readFieldAsLittleEndian to
// GPU-reported switch PDIs, reversing the byte order before hex encoding.
var expectedSwitchHexSet = map[string]struct{}{
	"90fd48d7b3c6b940": {},
	"25b23c47f129b5fd": {},
	"639659834ec14310": {},
	"aa0a158e029df6d0": {},
}

func switchPDIsForGPU() []byte {
	var b []byte
	for _, s := range [][]byte{switchA, switchB, switchC, switchD} {
		b = append(b, s...)
	}
	for i := 0; i < 14; i++ {
		b = append(b, make([]byte, pdiSize)...)
	}
	return b
}

func allGPUPDIs() []byte {
	var b []byte
	for _, g := range [][]byte{gpuPDI0, gpuPDI1, gpuPDI2, gpuPDI3, gpuPDI4, gpuPDI5, gpuPDI6, gpuPDI7} {
		b = append(b, g...)
	}
	return b
}

// Mirrors test_gpu_topology_check (line 32-43)
func TestGPUTopologyCheck(t *testing.T) {
	report := buildSPDMReport([]tlvEntry{
		{typ: fieldPDI, val: switchPDIsForGPU()},
	})
	fields, err := parseSPDMOpaqueFields(report)
	if err != nil {
		t.Fatalf("parseSPDMOpaqueFields: %v", err)
	}
	raw := fields[fieldPDI]
	pdis, err := parsePDISet(raw, len(raw)/pdiSize, true)
	if err != nil {
		t.Fatalf("parsePDISet: %v", err)
	}
	if len(pdis) != 4 {
		t.Fatalf("expected 4 unique switches, got %d", len(pdis))
	}
	if !setsEqual(pdis, expectedSwitchHexSet) {
		t.Errorf("switch PDIs = %v, want %v", pdis, expectedSwitchHexSet)
	}
}

// Mirrors test_switch_topology_check (line 52-68)
//
// Like the Python reference, GPU switch PDIs are LE-reversed while
// switch device PDIs use direct hex. The switchDevA-D byte arrays are
// the byte-reverse of switchA-D, matching real NVIDIA SPDM hardware behavior.
func TestSwitchTopologyCheck(t *testing.T) {
	gpuReports := make([][]byte, 8)
	for i := range gpuReports {
		gpuReports[i] = buildSPDMReport([]tlvEntry{
			{typ: fieldPDI, val: switchPDIsForGPU()},
		})
	}
	switchReports := [][]byte{
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevA}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevB}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevC}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevD}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
	}
	if err := validateTopology(gpuReports, switchReports); err != nil {
		t.Fatalf("expected topology OK, got: %v", err)
	}
}

// Mirrors test_gpu_topology_check_with_disabled_links (line 70-85)
//
// Same switch PDIs plus one b'\x00\x00\x00\x00\x00\x00\x00\x00' entry.
func TestGPUTopologyCheckWithDisabledLinks(t *testing.T) {
	var pdis []byte
	for _, s := range [][]byte{switchA, switchB, switchC, switchD} {
		pdis = append(pdis, s...)
	}
	pdis = append(pdis, make([]byte, pdiSize)...) // b'\x00\x00\x00\x00\x00\x00\x00\x00'
	for i := 0; i < 13; i++ {
		pdis = append(pdis, make([]byte, pdiSize)...)
	}

	report := buildSPDMReport([]tlvEntry{
		{typ: fieldPDI, val: pdis},
	})
	fields, err := parseSPDMOpaqueFields(report)
	if err != nil {
		t.Fatalf("parseSPDMOpaqueFields: %v", err)
	}
	raw := fields[fieldPDI]
	set, err := parsePDISet(raw, len(raw)/pdiSize, true)
	if err != nil {
		t.Fatalf("parsePDISet: %v", err)
	}
	if len(set) != 4 {
		t.Fatalf("expected 4 unique switches (zero skipped), got %d", len(set))
	}
	if !setsEqual(set, expectedSwitchHexSet) {
		t.Errorf("switch PDIs = %v, want %v", set, expectedSwitchHexSet)
	}
}

// --- Additional failure cases (no Python equivalents) ---

func TestValidateTopologyWrongGPUCount(t *testing.T) {
	if err := validateTopology(make([][]byte, 7), make([][]byte, 4)); err == nil {
		t.Fatal("expected error for wrong GPU count")
	}
}

func TestValidateTopologyWrongSwitchCount(t *testing.T) {
	if err := validateTopology(make([][]byte, 8), make([][]byte, 3)); err == nil {
		t.Fatal("expected error for wrong switch count")
	}
}

func TestValidateTopologyGPUSeesDifferentSwitches(t *testing.T) {
	gpuReports := make([][]byte, 8)
	for i := range gpuReports {
		gpuReports[i] = buildSPDMReport([]tlvEntry{
			{typ: fieldPDI, val: switchPDIsForGPU()},
		})
	}

	rogueSwitch := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	var roguePDIs []byte
	roguePDIs = append(roguePDIs, rogueSwitch...)
	roguePDIs = append(roguePDIs, switchB...)
	roguePDIs = append(roguePDIs, switchC...)
	roguePDIs = append(roguePDIs, switchD...)
	for i := 0; i < 14; i++ {
		roguePDIs = append(roguePDIs, make([]byte, pdiSize)...)
	}
	gpuReports[3] = buildSPDMReport([]tlvEntry{
		{typ: fieldPDI, val: roguePDIs},
	})

	switchReports := [][]byte{
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevA}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevB}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevC}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevD}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
	}
	if err := validateTopology(gpuReports, switchReports); err == nil {
		t.Fatal("expected topology error for mismatched switch set")
	}
}

func TestValidateTopologySwitchPDINotInGPUSet(t *testing.T) {
	gpuReports := make([][]byte, 8)
	for i := range gpuReports {
		gpuReports[i] = buildSPDMReport([]tlvEntry{
			{typ: fieldPDI, val: switchPDIsForGPU()},
		})
	}

	rogueSwitch := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF}
	switchReports := [][]byte{
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevA}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: rogueSwitch}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevC}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevD}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
	}
	if err := validateTopology(gpuReports, switchReports); err == nil {
		t.Fatal("expected topology error for unknown switch PDI")
	}
}

func TestValidateTopologyDuplicateSwitchPDI(t *testing.T) {
	gpuReports := make([][]byte, 8)
	for i := range gpuReports {
		gpuReports[i] = buildSPDMReport([]tlvEntry{
			{typ: fieldPDI, val: switchPDIsForGPU()},
		})
	}
	// switch[2] reuses switchDevA's PDI: each PDI is in the GPU-reported set,
	// but the four reports do not cover four distinct devices.
	switchReports := [][]byte{
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevA}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevB}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevA}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
		buildSPDMReport([]tlvEntry{{typ: fieldPDI, val: switchDevD}, {typ: fieldGPUPDIs, val: allGPUPDIs()}}),
	}
	if err := validateTopology(gpuReports, switchReports); err == nil {
		t.Fatal("expected topology error for duplicate switch device PDI")
	}
}

// Verify our hex encoding of the reference PDIs matches expectations.
func TestReferencePDIHexEncoding(t *testing.T) {
	// switchA raw bytes: b'@\xb9\xc6\xb3\xd7H\xfd\x90'
	if got := hex.EncodeToString(switchA); got != "40b9c6b3d748fd90" {
		t.Errorf("switchA hex = %s", got)
	}
	// readFieldAsLittleEndian(switchA) must match the Python LE-read value
	if got := readFieldAsLittleEndian(switchA); got != "90fd48d7b3c6b940" {
		t.Errorf("readFieldAsLittleEndian(switchA) = %s", got)
	}
	// switchDevA: b'\x90\xfdH\xd7\xb3\xc6\xb9@' (Python line 47, byte-reverse of switchA)
	if got := hex.EncodeToString(switchDevA); got != "90fd48d7b3c6b940" {
		t.Errorf("switchDevA hex = %s", got)
	}
	// gpuPDI2: b"\xbf\\\xc6'\xc8\x13\xae\xd8"
	if got := hex.EncodeToString(gpuPDI2); got != "bf5cc627c813aed8" {
		t.Errorf("gpuPDI2 hex = %s", got)
	}
}

func TestCheckOpaqueDataVersion2Bytes(t *testing.T) {
	report := buildSPDMReport([]tlvEntry{
		{typ: fieldOpaqueDataVersion, val: []byte{0x03, 0x00}},
		{typ: fieldPDI, val: switchPDIsForGPU()},
	})
	fields, err := parseSPDMOpaqueFields(report)
	if err != nil {
		t.Fatalf("parseSPDMOpaqueFields: %v", err)
	}
	raw := fields[fieldOpaqueDataVersion]
	if len(raw) != 2 {
		t.Fatalf("expected 2-byte version field, got %d", len(raw))
	}
	checkOpaqueDataVersion(fields, "test-device")
}

func TestCheckOpaqueDataVersion4Bytes(t *testing.T) {
	report := buildSPDMReport([]tlvEntry{
		{typ: fieldOpaqueDataVersion, val: []byte{0x05, 0x00, 0x00, 0x00}},
		{typ: fieldPDI, val: switchPDIsForGPU()},
	})
	fields, err := parseSPDMOpaqueFields(report)
	if err != nil {
		t.Fatalf("parseSPDMOpaqueFields: %v", err)
	}
	raw := fields[fieldOpaqueDataVersion]
	if len(raw) != 4 {
		t.Fatalf("expected 4-byte version field, got %d", len(raw))
	}
	checkOpaqueDataVersion(fields, "test-device")
}

func TestCheckOpaqueDataVersion1Byte(t *testing.T) {
	report := buildSPDMReport([]tlvEntry{
		{typ: fieldOpaqueDataVersion, val: []byte{0x07}},
		{typ: fieldPDI, val: switchPDIsForGPU()},
	})
	fields, err := parseSPDMOpaqueFields(report)
	if err != nil {
		t.Fatalf("parseSPDMOpaqueFields: %v", err)
	}
	checkOpaqueDataVersion(fields, "test-device")
}

func TestCheckOpaqueDataVersionMissing(t *testing.T) {
	report := buildSPDMReport([]tlvEntry{
		{typ: fieldPDI, val: switchPDIsForGPU()},
	})
	fields, err := parseSPDMOpaqueFields(report)
	if err != nil {
		t.Fatalf("parseSPDMOpaqueFields: %v", err)
	}
	// should not panic when field is absent
	checkOpaqueDataVersion(fields, "test-device")
}
