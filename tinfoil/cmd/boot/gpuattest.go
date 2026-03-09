package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

const (
	nvattestTimeout   = 5 * time.Minute
	nvidiaVendorID    = "0x10de"
	multiGPUThreshold = 12 // 8 GPUs + 4 NVSwitches
)

// detectGPUCount scans PCI devices and returns 0, 1, or 8.
func detectGPUCount() (int, error) {
	pciPath := "/sys/bus/pci/devices"
	entries, err := os.ReadDir(pciPath)
	if err != nil {
		return 0, fmt.Errorf("reading PCI devices: %w", err)
	}
	count := 0
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(pciPath, entry.Name(), "vendor"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == nvidiaVendorID {
			count++
		}
	}
	if count >= multiGPUThreshold {
		return 8, nil
	}
	if count > 0 {
		return 1, nil
	}
	return 0, nil
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
func verifyGPUAttestation(expectedGPUs int) (*GPURawEvidence, error) {
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

	if expectedGPUs > 1 {
		if err := runNvattest("nvswitch"); err != nil {
			return nil, err
		}

		log.Println("Collecting NVSwitch evidence for topology validation")
		switchReports, switchRaw, err := collectEvidence("nvswitch")
		if err != nil {
			return nil, fmt.Errorf("collecting switch evidence: %w", err)
		}
		evidence.Switch = switchRaw

		log.Println("Validating PPCIe topology")
		if err := validateTopology(gpuReports, switchReports); err != nil {
			return nil, fmt.Errorf("topology validation failed: %w", err)
		}
	}

	if err := setGPUReadyState(true); err != nil {
		return nil, fmt.Errorf("enabling GPU ready state: %w", err)
	}

	ok = true
	log.Println("GPU attestation verified")
	return evidence, nil
}
