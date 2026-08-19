package attestation

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	envelope "github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	"tinfoil/internal/nvml"
)

// GPUEvidence holds the raw attestation evidence and certificate for a single GPU.
type GPUEvidence struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"` // base64 attestation cert chain
	Evidence    string `json:"evidence"`    // base64 SPDM attestation report
	Nonce       string `json:"nonce"`       // hex nonce
}

// GPUEvidenceCollection is the top-level structure matching nvattest's JSON output.
type GPUEvidenceCollection struct {
	Evidences []GPUEvidence `json:"evidences"`
}

const (
	GPUArchHopper    = "HOPPER"
	GPUArchBlackwell = "BLACKWELL"
)

var archNames = map[nvml.DeviceArchitecture]string{
	nvml.DEVICE_ARCH_HOPPER:    GPUArchHopper,
	nvml.DEVICE_ARCH_BLACKWELL: GPUArchBlackwell,
}

// Arch returns the architecture of the collected GPUs (shapes are always
// homogeneous), or "" when no evidence was collected.
func (c *GPUEvidenceCollection) Arch() string {
	if c == nil || len(c.Evidences) == 0 {
		return ""
	}
	return c.Evidences[0].Arch
}

// RequiresNVSwitchEvidence reports whether a GPU shape must carry NVSwitch
// evidence, rejecting shapes the fleet cannot produce. Hopper ships only in
// 1-GPU and 8-GPU shapes; the 8-GPU HGX baseboard routes GPU traffic through
// NVSwitches that must be attested. Blackwell (MPT) shapes never expose
// NVSwitches to the guest, at any GPU count.
func RequiresNVSwitchEvidence(arch string, gpuCount int) (bool, error) {
	switch arch {
	case GPUArchHopper:
		switch gpuCount {
		case 1:
			return false, nil
		case 8:
			return true, nil
		default:
			return false, fmt.Errorf("hopper shapes have 1 or 8 GPUs, got %d", gpuCount)
		}
	case GPUArchBlackwell:
		return false, nil
	default:
		if gpuCount <= 1 {
			return false, nil
		}
		return false, fmt.Errorf("unsupported multi-GPU architecture %q", arch)
	}
}

// CollectGPUEvidence collects fresh attestation evidence from all GPUs using
// NVML directly (no nvattest CLI). The nonce must be exactly 32 bytes.
func CollectGPUEvidence(nonce [32]byte) (*GPUEvidenceCollection, error) {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("nvml.Init: %s", nvml.ErrorString(ret))
	}
	defer nvml.Shutdown()

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("DeviceGetCount: %s", nvml.ErrorString(ret))
	}

	var evidences []GPUEvidence
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("DeviceGetHandleByIndex(%d): %s", i, nvml.ErrorString(ret))
		}

		arch, ret := device.GetArchitecture()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GetArchitecture(%d): %s", i, nvml.ErrorString(ret))
		}
		archName, ok := archNames[arch]
		if !ok {
			archName = fmt.Sprintf("UNKNOWN_%d", arch)
		}

		// Collect attestation report with nonce
		var report nvml.ConfComputeGpuAttestationReport
		report.Nonce = nonce
		ret = device.GetConfComputeGpuAttestationReport(&report)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GetConfComputeGpuAttestationReport(%d): %s", i, nvml.ErrorString(ret))
		}

		// Collect certificate chain
		cert, ret := device.GetConfComputeGpuCertificate()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GetConfComputeGpuCertificate(%d): %s", i, nvml.ErrorString(ret))
		}

		if report.AttestationReportSize > uint32(len(report.AttestationReport)) {
			return nil, fmt.Errorf("GPU %d: attestation report size %d exceeds buffer", i, report.AttestationReportSize)
		}
		if cert.AttestationCertChainSize > uint32(len(cert.AttestationCertChain)) {
			return nil, fmt.Errorf("GPU %d: cert chain size %d exceeds buffer", i, cert.AttestationCertChainSize)
		}

		evidences = append(evidences, GPUEvidence{
			Arch:        archName,
			Certificate: base64.StdEncoding.EncodeToString(cert.AttestationCertChain[:cert.AttestationCertChainSize]),
			Evidence:    base64.StdEncoding.EncodeToString(report.AttestationReport[:report.AttestationReportSize]),
			Nonce:       hex.EncodeToString(nonce[:]),
		})
	}

	return &GPUEvidenceCollection{Evidences: evidences}, nil
}

// CollectNVSwitchEvidence collects fresh NVSwitch attestation evidence via
// the nvattest CLI (NSCQ is not exposed through go-nvml). The nonce must be
// exactly 32 bytes.
func CollectNVSwitchEvidence(nonce [32]byte) (json.RawMessage, error) {
	nonceHex := hex.EncodeToString(nonce[:])

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "nvattest", "collect-evidence",
		"--device", "nvswitch",
		"--nonce", nonceHex,
		"--format", "json",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("nvattest collect-evidence nvswitch: %w", err)
	}

	if !json.Valid(out) {
		return nil, fmt.Errorf("nvattest returned invalid JSON")
	}
	if err := validateNVSwitchEvidence(out); err != nil {
		return nil, err
	}

	return json.RawMessage(out), nil
}

func validateNVSwitchEvidence(raw []byte) error {
	var result struct {
		ResultCode    *int   `json:"result_code"`
		ResultMessage string `json:"result_message"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("parsing NVSwitch evidence status: %w", err)
	}
	if result.ResultCode == nil {
		return fmt.Errorf("NVSwitch evidence response is missing result_code")
	}
	if *result.ResultCode != 0 {
		return fmt.Errorf("NVSwitch evidence collection failed: %s (code %d)", result.ResultMessage, *result.ResultCode)
	}
	return nil
}

// nvswitchEvidenceV1Format identifies the raw nvattest NVSwitch evidence
// payload. Not yet in the verifier registry: v3 verifiers accept unknown
// device evidence item formats as long as the appraisal policy does not
// require verifying that device.
const nvswitchEvidenceV1Format = "https://tinfoil.sh/format/nvidia-nvswitch-evidence/v1"

// DeviceEvidenceFromGPUCollection converts collected GPU evidence into v3
// device_evidence items (one per GPU, ids gpu0..gpuN-1).
func DeviceEvidenceFromGPUCollection(collection *GPUEvidenceCollection) ([]envelope.DeviceEvidenceItem, error) {
	if collection == nil {
		return nil, nil
	}
	items := make([]envelope.DeviceEvidenceItem, 0, len(collection.Evidences))
	for i, evidence := range collection.Evidences {
		payload, err := json.Marshal(evidence)
		if err != nil {
			return nil, fmt.Errorf("serializing GPU %d evidence: %w", i, err)
		}
		items = append(items, envelope.DeviceEvidenceItem{
			ID:       fmt.Sprintf("gpu%d", i),
			Kind:     "gpu",
			Vendor:   "nvidia",
			Format:   envelope.NvidiaGPUEvidenceV1Format,
			Evidence: payload,
		})
	}
	return items, nil
}

// DeviceEvidenceFromNVSwitch wraps raw nvattest NVSwitch output as a v3
// device_evidence item.
func DeviceEvidenceFromNVSwitch(raw json.RawMessage) []envelope.DeviceEvidenceItem {
	if len(raw) == 0 {
		return nil
	}
	return []envelope.DeviceEvidenceItem{{
		ID:       "nvswitch0",
		Kind:     "nvswitch",
		Vendor:   "nvidia",
		Format:   nvswitchEvidenceV1Format,
		Evidence: raw,
	}}
}

// CollectDeviceEvidence collects the complete nonce-bound device evidence for
// a measured GPU shape. CPU-only shapes return an empty evidence set.
func CollectDeviceEvidence(nonce [32]byte, expectedGPUs int) ([]envelope.DeviceEvidenceItem, error) {
	if expectedGPUs < 0 {
		return nil, fmt.Errorf("expected GPU count must not be negative")
	}
	if expectedGPUs == 0 {
		return nil, nil
	}

	gpuEvidence, err := CollectGPUEvidence(nonce)
	if err != nil {
		return nil, fmt.Errorf("collecting GPU evidence: %w", err)
	}
	if got := len(gpuEvidence.Evidences); got != expectedGPUs {
		return nil, fmt.Errorf("GPU evidence count mismatch: expected %d, got %d", expectedGPUs, got)
	}
	deviceEvidence, err := DeviceEvidenceFromGPUCollection(gpuEvidence)
	if err != nil {
		return nil, fmt.Errorf("encoding GPU evidence: %w", err)
	}
	requiresSwitch, err := RequiresNVSwitchEvidence(gpuEvidence.Arch(), expectedGPUs)
	if err != nil {
		return nil, fmt.Errorf("validating GPU shape: %w", err)
	}
	if !requiresSwitch {
		return deviceEvidence, nil
	}
	nvswitchEvidence, err := CollectNVSwitchEvidence(nonce)
	if err != nil {
		return nil, fmt.Errorf("collecting NVSwitch evidence: %w", err)
	}
	return append(deviceEvidence, DeviceEvidenceFromNVSwitch(nvswitchEvidence)...), nil
}
