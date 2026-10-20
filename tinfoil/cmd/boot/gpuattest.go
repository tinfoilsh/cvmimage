package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"tinfoil/internal/attestation"
	"tinfoil/internal/nvml"
)

const nvattestTimeout = 5 * time.Minute

func detectGPUArchitectures(expectedGPUs int) ([]nvml.DeviceArchitecture, error) {
	if ret := nvml.Init(); ret != nvml.SUCCESS {
		return nil, fmt.Errorf("nvml.Init: %s", nvml.ErrorString(ret))
	}
	defer nvml.Shutdown()

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("DeviceGetCount: %s", nvml.ErrorString(ret))
	}
	if count != expectedGPUs {
		return nil, fmt.Errorf("expected %d GPUs, detected %d", expectedGPUs, count)
	}
	architectures := make([]nvml.DeviceArchitecture, count)
	for i := range architectures {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("DeviceGetHandleByIndex(%d): %s", i, nvml.ErrorString(ret))
		}
		architectures[i], ret = device.GetArchitecture()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GetArchitecture(%d): %s", i, nvml.ErrorString(ret))
		}
	}
	return architectures, nil
}

func validateGPUSecurity(architectures []nvml.DeviceArchitecture, allowUnencryptedNVLink bool) (string, error) {
	if len(architectures) == 0 {
		return "", fmt.Errorf("no GPU architectures detected")
	}
	var arch string
	for i, architecture := range architectures {
		switch architecture {
		case nvml.DEVICE_ARCH_HOPPER:
			arch = attestation.GPUArchHopper
		case nvml.DEVICE_ARCH_BLACKWELL:
			arch = attestation.GPUArchBlackwell
		default:
			return "", fmt.Errorf("GPU %d has unsupported architecture %d", i, architecture)
		}
		if architecture != architectures[0] {
			return "", fmt.Errorf("mixed GPU architectures are unsupported")
		}
	}
	if arch == attestation.GPUArchHopper && len(architectures) > 1 && !allowUnencryptedNVLink {
		return "", fmt.Errorf("multi-GPU Hopper (H100/H200) uses unencrypted NVLink; set security.allow-unencrypted-nvlink: true to allow it")
	}
	return arch, nil
}

func runNvattest(device string) error {
	log.Printf("Running nvattest attest for %s", device)
	ctx, cancel := context.WithTimeout(context.Background(), nvattestTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nvattest", "attest", "--device", device, "--verifier", "local")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nvattest %s timed out after %s", device, nvattestTimeout)
		}
		return fmt.Errorf("nvattest %s attestation failed: %w", device, err)
	}
	return nil
}

type nvattestEvidenceOutput struct {
	Evidences []struct {
		Evidence    string `json:"evidence"`
		Certificate string `json:"certificate"`
	} `json:"evidences"`
	ResultCode    int    `json:"result_code"`
	ResultMessage string `json:"result_message"`
}

func collectEvidence(device string) ([][]byte, json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nvattestTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nvattest", "collect-evidence", "--device", device, "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, nil, fmt.Errorf("nvattest collect-evidence %s timed out after %s", device, nvattestTimeout)
		}
		return nil, nil, fmt.Errorf("nvattest collect-evidence %s: %w", device, err)
	}

	var parsed nvattestEvidenceOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, nil, fmt.Errorf("parsing collect-evidence %s JSON: %w", device, err)
	}
	if parsed.ResultCode != 0 {
		return nil, nil, fmt.Errorf("collect-evidence %s failed: %s (code %d)", device, parsed.ResultMessage, parsed.ResultCode)
	}

	reports := make([][]byte, 0, len(parsed.Evidences))
	for i, ev := range parsed.Evidences {
		raw, err := base64.StdEncoding.DecodeString(ev.Evidence)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding evidence[%d]: %w", i, err)
		}
		reports = append(reports, raw)
	}
	return reports, json.RawMessage(out), nil
}

func setGPUReadyState(accepting bool) error {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		return fmt.Errorf("nvml.Init: %s", nvml.ErrorString(ret))
	}
	defer nvml.Shutdown()

	var state uint32 = nvml.CC_ACCEPTING_CLIENT_REQUESTS_FALSE
	if accepting {
		state = nvml.CC_ACCEPTING_CLIENT_REQUESTS_TRUE
	}

	ret = nvml.SystemSetConfComputeGpusReadyState(state)
	if ret != nvml.SUCCESS {
		return fmt.Errorf("SystemSetConfComputeGpusReadyState: %s", nvml.ErrorString(ret))
	}
	log.Printf("GPU ready state set to %v", accepting)
	return nil
}

// GPURawEvidence holds the raw nvattest collect-evidence JSON output.
// Each device's evidence contains hardware-signed SPDM reports and cert chains.
type GPURawEvidence struct {
	GPU    json.RawMessage `json:"gpu,omitempty"`
	Switch json.RawMessage `json:"nvswitch,omitempty"`
}

// verifyGPUAttestation runs attestation for the expected number of GPUs (1 or 8).
// Returns the raw evidence for inclusion in the attestation envelope.
func verifyGPUAttestation(expectedGPUs int, arch string) (*GPURawEvidence, error) {
	ok := false
	defer func() {
		if !ok {
			if err := setGPUReadyState(false); err != nil {
				log.Printf("WARNING: failed to disable GPU ready state: %v", err)
			}
		}
	}()

	if err := runNvattest("gpu"); err != nil {
		return nil, err
	}

	evidence := &GPURawEvidence{}

	log.Println("Collecting GPU evidence")
	gpuReports, gpuRaw, err := collectEvidence("gpu")
	if err != nil {
		return nil, fmt.Errorf("collecting GPU evidence: %w", err)
	}
	if len(gpuReports) != expectedGPUs {
		return nil, fmt.Errorf("expected %d GPU reports, got %d", expectedGPUs, len(gpuReports))
	}
	evidence.GPU = gpuRaw

	needSwitch, err := attestation.RequiresNVSwitchEvidence(arch, expectedGPUs)
	if err != nil {
		return nil, fmt.Errorf("GPU shape validation: %w", err)
	}
	if needSwitch {
		if err := runNvattest("nvswitch"); err != nil {
			return nil, err
		}
		log.Println("Collecting NVSwitch evidence for topology validation")
		switchReports, switchRaw, err := collectEvidence("nvswitch")
		if err != nil {
			return nil, fmt.Errorf("collecting switch evidence: %w", err)
		}
		evidence.Switch = switchRaw
		log.Printf("Validating Hopper PPCIe topology (%d GPUs, %d switches)", expectedGPUs, hopperSwitchCount)
		if err := validateTopology(gpuReports, switchReports, expectedGPUs, hopperSwitchCount); err != nil {
			return nil, fmt.Errorf("topology validation failed: %w", err)
		}
	} else if expectedGPUs > 1 {
		log.Printf("No in-guest NVSwitch evidence for %d %s GPUs", expectedGPUs, arch)
	}

	if err := setGPUReadyState(true); err != nil {
		return nil, fmt.Errorf("enabling GPU ready state: %w", err)
	}

	ok = true
	log.Println("GPU attestation verified")
	return evidence, nil
}
