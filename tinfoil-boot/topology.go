package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

const (
	pdiSize = 8

	// SPDM GET_MEASUREMENT message layout
	// [Request (37 bytes)][Response: Header(8) | MeasurementRecord(variable) | Nonce(32) | OpaqueLen(2) | OpaqueData(variable) | Signature]
	spdmRequestLen    = 37
	spdmRespHeaderLen = 8
	spdmNonceLen      = 32

	// Known SPDM versions (major<<4 | minor). Topology parsing is validated
	// against these; unknown versions produce a warning.
	spdmVersion11 = 0x11
	spdmVersion12 = 0x12

	// Opaque data field IDs (TLV type values from NVIDIA SPDM spec)
	fieldPDI               = 22 // GPU report: switch PDIs (LE byte order); switch report: device PDI
	fieldGPUPDIs           = 26 // Switch report: connected GPU PDIs, followed by port map
	fieldOpaqueDataVersion = 34 // Opaque data format version

	// HGX H100/H200 topology: 8 GPUs connected to 4 NVSwitches
	expectedGPUCount    = 8
	expectedSwitchCount = 4
)

// checkSPDMVersion validates the SPDM version byte in the response and warns
// if it's not a known version. Returns an error only if the report is too short.
func checkSPDMVersion(report []byte, deviceLabel string) {
	if len(report) <= spdmRequestLen {
		return
	}
	version := report[spdmRequestLen] // first byte of response is SPDMVersion
	switch version {
	case spdmVersion11, spdmVersion12:
		// known versions
	default:
		log.Printf("WARNING: %s has unexpected SPDM version 0x%02x (expected 0x11 or 0x12), topology parsing may be unreliable", deviceLabel, version)
	}
}

// checkOpaqueDataVersion logs the opaque data format version (field 34) if
// present, and warns if it's unexpected.
func checkOpaqueDataVersion(fields map[uint16][]byte, deviceLabel string) {
	raw, ok := fields[fieldOpaqueDataVersion]
	if !ok {
		return
	}
	var version uint64
	for i, b := range raw {
		version |= uint64(b) << (8 * i)
	}
	log.Printf("%s opaque data version: %d", deviceLabel, version)
}

// parseSPDMOpaqueFields extracts the TLV opaque data fields from a raw SPDM
// attestation report (request+response concatenated).
func parseSPDMOpaqueFields(report []byte) (map[uint16][]byte, error) {
	if len(report) <= spdmRequestLen+spdmRespHeaderLen {
		return nil, fmt.Errorf("report too short (%d bytes)", len(report))
	}
	resp := report[spdmRequestLen:]

	// MeasurementRecordLength is 3-byte LE at response offset 5
	measLen := int(resp[5]) | int(resp[6])<<8 | int(resp[7])<<16

	// OpaqueLength is 2-byte LE immediately after nonce
	olOff := spdmRespHeaderLen + measLen + spdmNonceLen
	if olOff+2 > len(resp) {
		return nil, fmt.Errorf("report truncated before opaque length")
	}
	opaqueLen := int(binary.LittleEndian.Uint16(resp[olOff : olOff+2]))

	data := resp[olOff+2:]
	if len(data) < opaqueLen {
		return nil, fmt.Errorf("report truncated in opaque data")
	}
	data = data[:opaqueLen]

	// Parse TLV entries: [Type(2) | Size(2) | Value(Size)]...
	fields := make(map[uint16][]byte)
	for off := 0; off+4 <= len(data); {
		typ := binary.LittleEndian.Uint16(data[off : off+2])
		sz := int(binary.LittleEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if off+sz > len(data) {
			return nil, fmt.Errorf("opaque TLV overflow: type=%d size=%d", typ, sz)
		}
		fields[typ] = data[off : off+sz]
		off += sz
	}
	return fields, nil
}

// readFieldAsLittleEndian reverses the byte order and returns a hex string.
// Mirrors the Python reference: nvtrust read_field_as_little_endian.
func readFieldAsLittleEndian(data []byte) string {
	reversed := make([]byte, len(data))
	for i, b := range data {
		reversed[len(data)-1-i] = b
	}
	return hex.EncodeToString(reversed)
}

// parsePDISet splits raw bytes into a set of 8-byte hex-encoded PDIs,
// skipping zero entries (disabled links). When littleEndian is true, each
// 8-byte chunk is byte-reversed before hex encoding (matching the NVIDIA
// convention for GPU-reported switch PDIs).
func parsePDISet(raw []byte, count int, littleEndian bool) (map[string]struct{}, error) {
	need := count * pdiSize
	if len(raw) < need {
		return nil, fmt.Errorf("PDI data too short: %d < %d", len(raw), need)
	}
	set := make(map[string]struct{}, count)
	for i := 0; i < need; i += pdiSize {
		var s string
		if littleEndian {
			s = readFieldAsLittleEndian(raw[i : i+pdiSize])
		} else {
			s = hex.EncodeToString(raw[i : i+pdiSize])
		}
		if s == "0000000000000000" {
			continue
		}
		set[s] = struct{}{}
	}
	return set, nil
}

func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// validateTopology cross-checks GPU and switch attestation reports to verify
// the PPCIe fabric forms a correct 8-GPU / 4-switch mesh.
//
// For each GPU: extract the switch PDIs from opaque field 22 and verify all
// GPUs report the same 4 switches.
// For each switch: verify its own PDI (field 22) is in the GPU-reported set,
// and that the GPU PDIs from field 26 are the same 8 GPUs across all switches.
func validateTopology(gpuReports, switchReports [][]byte) error {
	if len(gpuReports) != expectedGPUCount {
		return fmt.Errorf("expected %d GPU reports, got %d", expectedGPUCount, len(gpuReports))
	}
	if len(switchReports) != expectedSwitchCount {
		return fmt.Errorf("expected %d switch reports, got %d", expectedSwitchCount, len(switchReports))
	}

	// GPU side: every GPU must see exactly 4 unique switches, identical across all GPUs
	var expectedSwitches map[string]struct{}
	for i, report := range gpuReports {
		label := fmt.Sprintf("GPU[%d]", i)
		checkSPDMVersion(report, label)
		fields, err := parseSPDMOpaqueFields(report)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if i == 0 {
			checkOpaqueDataVersion(fields, label)
		}
		raw, ok := fields[fieldPDI]
		if !ok {
			return fmt.Errorf("%s: missing switch PDI field", label)
		}
		switchPDIs, err := parsePDISet(raw, len(raw)/pdiSize, true)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if len(switchPDIs) != expectedSwitchCount {
			return fmt.Errorf("%s sees %d switches, expected %d", label, len(switchPDIs), expectedSwitchCount)
		}
		if expectedSwitches == nil {
			expectedSwitches = switchPDIs
		} else if !setsEqual(expectedSwitches, switchPDIs) {
			return fmt.Errorf("%s switch set differs from GPU[0]", label)
		}
	}
	log.Printf("GPU topology OK: all %d GPUs see the same %d switches", expectedGPUCount, expectedSwitchCount)

	// Switch side: each switch's own PDI must be in the GPU-reported set,
	// and each must see exactly 8 unique GPUs, identical across all switches
	var expectedGPUs map[string]struct{}
	for i, report := range switchReports {
		label := fmt.Sprintf("switch[%d]", i)
		checkSPDMVersion(report, label)
		fields, err := parseSPDMOpaqueFields(report)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if i == 0 {
			checkOpaqueDataVersion(fields, label)
		}

		rawPDI, ok := fields[fieldPDI]
		if !ok {
			return fmt.Errorf("%s: missing device PDI field", label)
		}
		devicePDI := hex.EncodeToString(rawPDI)
		if _, ok := expectedSwitches[devicePDI]; !ok {
			return fmt.Errorf("%s PDI %s not in GPU-reported switch set", label, devicePDI)
		}

		rawGPUs, ok := fields[fieldGPUPDIs]
		if !ok {
			return fmt.Errorf("%s: missing GPU PDI field", label)
		}
		gpuPDIs, err := parsePDISet(rawGPUs, expectedGPUCount, false)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if len(gpuPDIs) != expectedGPUCount {
			return fmt.Errorf("%s sees %d GPUs, expected %d", label, len(gpuPDIs), expectedGPUCount)
		}
		if expectedGPUs == nil {
			expectedGPUs = gpuPDIs
		} else if !setsEqual(expectedGPUs, gpuPDIs) {
			return fmt.Errorf("%s GPU set differs from switch[0]", label)
		}
	}
	log.Printf("Switch topology OK: all %d switches see the same %d GPUs", expectedSwitchCount, expectedGPUCount)

	return nil
}
