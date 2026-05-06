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
	nvattestTimeout = 5 * time.Minute
	nvidiaVendorID  = "0x10de"
	nvidiaGPUClass  = "0x030200" // 3D controller
	gpuDeviceIDH100 = "0x2331"
	gpuDeviceIDH200 = "0x2335"
	gpuDeviceIDB200 = "0x2901"
)

// forEachNVIDIAGPU iterates over PCI devices that are NVIDIA GPUs
// (vendor 0x10de + 3D-controller class), invoking fn with each device's
// sysfs entry name. Walking stops if fn returns false.
func forEachNVIDIAGPU(fn func(entryName string) bool) error {
	const pciPath = "/sys/bus/pci/devices"
	entries, err := os.ReadDir(pciPath)
	if err != nil {
		return fmt.Errorf("reading PCI devices: %w", err)
	}
	for _, entry := range entries {
		vendor, err := os.ReadFile(filepath.Join(pciPath, entry.Name(), "vendor"))
		if err != nil || strings.TrimSpace(string(vendor)) != nvidiaVendorID {
			continue
		}
		class, err := os.ReadFile(filepath.Join(pciPath, entry.Name(), "class"))
		if err != nil || strings.TrimSpace(string(class)) != nvidiaGPUClass {
			continue
		}
		if !fn(entry.Name()) {
			return nil
		}
	}
	return nil
}

// detectGPUCount returns the number of NVIDIA 3D-controller PCI devices
// in the guest. The caller validates against the config-declared count.
func detectGPUCount() (int, error) {
	count := 0
	if err := forEachNVIDIAGPU(func(string) bool { count++; return true }); err != nil {
		return 0, err
	}
	return count, nil
}

// detectGPUArch returns "h100", "h200", "b200", or "" from the first GPU.
func detectGPUArch() (string, error) {
	const pciPath = "/sys/bus/pci/devices"
	var arch string
	err := forEachNVIDIAGPU(func(entryName string) bool {
		device, err := os.ReadFile(filepath.Join(pciPath, entryName, "device"))
		if err != nil {
			return true
		}
		switch strings.TrimSpace(string(device)) {
		case gpuDeviceIDH100:
			arch = "h100"
		case gpuDeviceIDH200:
			arch = "h200"
		case gpuDeviceIDB200:
			arch = "b200"
		default:
			return true
		}
		return false
	})
	return arch, err
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

type dummyEvidenceEntry struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Nonce       string `json:"nonce"`
}

type dummyEvidenceOutput struct {
	Evidences     []dummyEvidenceEntry `json:"evidences"`
	ResultCode    int                  `json:"result_code"`
	ResultMessage string               `json:"result_message"`
}

// dummyGPUEvidence returns mock GPU evidence matching the nvattest JSON format.
func dummyGPUEvidence(gpuCount int) *GPURawEvidence {
	gpuOut := dummyEvidenceOutput{ResultCode: 0, ResultMessage: "dummy-attestation"}
	for range gpuCount {
		gpuOut.Evidences = append(gpuOut.Evidences, dummyEvidenceEntry{Arch: "DUMMY"})
	}
	gpuRaw, _ := json.Marshal(gpuOut)
	evidence := &GPURawEvidence{GPU: json.RawMessage(gpuRaw)}

	if gpuCount > 1 {
		switchOut := dummyEvidenceOutput{ResultCode: 0, ResultMessage: "dummy-attestation"}
		for range 4 {
			switchOut.Evidences = append(switchOut.Evidences, dummyEvidenceEntry{Arch: "DUMMY"})
		}
		switchRaw, _ := json.Marshal(switchOut)
		evidence.Switch = json.RawMessage(switchRaw)
	}
	return evidence
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
		arch, err := detectGPUArch()
		if err != nil {
			return nil, fmt.Errorf("detecting GPU arch: %w", err)
		}
		switch arch {
		case "b200":
			// B200 MPT: NVSwitches are not exposed to the guest.
			log.Printf("HGX B200 MPT: no in-guest NVSwitch evidence")

		case "h100", "h200", "":
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

		default:
			return nil, fmt.Errorf("unsupported multi-GPU arch %q for in-guest attestation", arch)
		}
	}

	if err := setGPUReadyState(true); err != nil {
		return nil, fmt.Errorf("enabling GPU ready state: %w", err)
	}

	ok = true
	log.Println("GPU attestation verified")
	return evidence, nil
}
