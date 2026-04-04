package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
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

var archNames = map[nvml.DeviceArchitecture]string{
	nvml.DEVICE_ARCH_HOPPER:    "HOPPER",
	nvml.DEVICE_ARCH_BLACKWELL: "BLACKWELL",
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

		evidences = append(evidences, GPUEvidence{
			Arch:        archName,
			Certificate: base64.StdEncoding.EncodeToString(cert.AttestationCertChain[:cert.AttestationCertChainSize]),
			Evidence:    base64.StdEncoding.EncodeToString(report.AttestationReport[:report.AttestationReportSize]),
			Nonce:       hex.EncodeToString(nonce[:]),
		})
	}

	return &GPUEvidenceCollection{Evidences: evidences}, nil
}
