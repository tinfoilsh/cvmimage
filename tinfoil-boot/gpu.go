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
	nvidiaVendorID    = "0x10de"
	multiGPUThreshold = 12 // 8 GPUs + 4 NVSwitches

	nvattestTimeout = 5 * time.Minute
)

type GPUInfo struct {
	HasNvidia   bool
	DeviceCount int
	IsMultiGPU  bool
}

func detectGPUs() (*GPUInfo, error) {
	info := &GPUInfo{}

	pciPath := "/sys/bus/pci/devices"
	entries, err := os.ReadDir(pciPath)
	if err != nil {
		return nil, fmt.Errorf("reading PCI devices: %w", err)
	}

	for _, entry := range entries {
		vendorPath := filepath.Join(pciPath, entry.Name(), "vendor")
		vendorData, err := os.ReadFile(vendorPath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(vendorData)) == nvidiaVendorID {
			info.DeviceCount++
		}
	}

	info.HasNvidia = info.DeviceCount > 0
	info.IsMultiGPU = info.DeviceCount >= multiGPUThreshold

	if info.HasNvidia {
		log.Printf("NVIDIA devices detected: %d (multi_gpu=%v)", info.DeviceCount, info.IsMultiGPU)
	}

	return info, nil
}

type nvatTestAttestOutput struct {
	Claims []json.RawMessage `json:"claims"`
	Evidences []struct {
		Evidence string `json:"evidence"`
	} `json:"evidences"`
	ResultCode    int    `json:"result_code"`
	ResultMessage string `json:"result_message"`
}

func runNvattest(device string) (*nvatTestAttestOutput, error) {
	log.Printf("Running nvattest attest for %s", device)
	ctx, cancel := context.WithTimeout(context.Background(), nvattestTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nvattest", "attest", "--device", device, "--verifier", "local", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("nvattest %s attestation timed out after %s", device, nvattestTimeout)
		}
		return nil, fmt.Errorf("nvattest %s attestation failed: %w", device, err)
	}

	var parsed nvatTestAttestOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("parsing nvattest %s JSON: %w", device, err)
	}
	if parsed.ResultCode != 0 {
		return nil, fmt.Errorf("nvattest %s attestation failed: %s (code %d)", device, parsed.ResultMessage, parsed.ResultCode)
	}

	return &parsed, nil
}

func extractEvidence(output *nvatTestAttestOutput) ([][]byte, error) {
	reports := make([][]byte, 0, len(output.Evidences))
	for i, ev := range output.Evidences {
		raw, err := base64.StdEncoding.DecodeString(ev.Evidence)
		if err != nil {
			return nil, fmt.Errorf("decoding evidence[%d]: %w", i, err)
		}
		reports = append(reports, raw)
	}
	return reports, nil
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

func verifyGPUAttestation(info *GPUInfo) error {
	ok := false
	defer func() {
		if !ok {
			if err := setGPUReadyState(false); err != nil {
				log.Printf("WARNING: failed to disable GPU ready state: %v", err)
			}
		}
	}()

	gpuResult, err := runNvattest("gpu")
	if err != nil {
		return err
	}

	if info.IsMultiGPU {
		switchResult, err := runNvattest("nvswitch")
		if err != nil {
			return err
		}

		gpuReports, err := extractEvidence(gpuResult)
		if err != nil {
			return fmt.Errorf("extracting GPU evidence: %w", err)
		}
		switchReports, err := extractEvidence(switchResult)
		if err != nil {
			return fmt.Errorf("extracting switch evidence: %w", err)
		}

		log.Println("Validating PPCIe topology")
		if err := validateTopology(gpuReports, switchReports); err != nil {
			return fmt.Errorf("topology validation failed: %w", err)
		}
	}

	if err := setGPUReadyState(true); err != nil {
		return fmt.Errorf("enabling GPU ready state: %w", err)
	}

	ok = true
	log.Println("GPU attestation verified")
	return nil
}
