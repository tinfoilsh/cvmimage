package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	gpuattestation "tinfoil/internal/attestation"
	"tinfoil/internal/nvml"
)

const (
	nvattestTimeout           = 5 * time.Minute
	gpuReadyStateAttempts     = 3
	gpuReadyStateRetryBackoff = 100 * time.Millisecond
)

var (
	commandContext              = exec.CommandContext
	generateGPUAttestationNonce = newGPUAttestationNonce
	enableVerifiedGPUs          = enableGPUsForIdentities
	disableGPUs                 = func() error { return setGPUReadyState(false) }
	gpuEvidenceTempDir          = "/run/tinfoil"
	initializeNVML              = nvml.Init
	shutdownNVML                = nvml.Shutdown
	snapshotLiveGPUIdentities   = liveGPUIdentities
	setGPUReadyStateValue       = nvml.SystemSetConfComputeGpusReadyState
)

type nvattestEvidenceEntry struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Nonce       string `json:"nonce"`
}

type nvattestEvidenceOutput struct {
	Evidences     json.RawMessage `json:"evidences"`
	ResultCode    int             `json:"result_code"`
	ResultMessage string          `json:"result_message"`
}

type nvattestAppraisalOutput struct {
	ResultCode    int    `json:"result_code"`
	ResultMessage string `json:"result_message"`
}

type verifiedEvidence struct {
	raw            json.RawMessage
	appraisalInput json.RawMessage
	reports        [][]byte
	identities     []string
	arches         []string
}

func newGPUAttestationNonce() ([32]byte, error) {
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nonce, fmt.Errorf("generating GPU attestation nonce: %w", err)
	}
	return nonce, nil
}

func collectAndAppraiseEvidence(device string, nonce [32]byte) (*verifiedEvidence, error) {
	raw, err := collectEvidence(device, nonce)
	if err != nil {
		return nil, err
	}
	parsed, err := parseEvidence(device, nonce, raw)
	if err != nil {
		return nil, err
	}
	if err := appraiseEvidence(device, nonce, parsed.appraisalInput); err != nil {
		return nil, err
	}
	return parsed, nil
}

func collectEvidence(device string, nonce [32]byte) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nvattestTimeout)
	defer cancel()

	nonceHex := hex.EncodeToString(nonce[:])
	cmd := commandContext(ctx, "nvattest", "collect-evidence",
		"--device", device,
		"--nonce", nonceHex,
		"--format", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("nvattest collect-evidence %s timed out after %s", device, nvattestTimeout)
		}
		return nil, fmt.Errorf("nvattest collect-evidence %s: %w", device, err)
	}
	return json.RawMessage(out), nil
}

func parseEvidence(device string, nonce [32]byte, raw json.RawMessage) (*verifiedEvidence, error) {
	var parsed nvattestEvidenceOutput
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parsing collect-evidence %s JSON: %w", device, err)
	}
	if parsed.ResultCode != 0 {
		return nil, fmt.Errorf("collect-evidence %s failed: %s (code %d)", device, parsed.ResultMessage, parsed.ResultCode)
	}
	var entries []nvattestEvidenceEntry
	if err := json.Unmarshal(parsed.Evidences, &entries); err != nil {
		return nil, fmt.Errorf("parsing collect-evidence %s entries: %w", device, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("collect-evidence %s returned no evidence", device)
	}

	expectedNonce := hex.EncodeToString(nonce[:])
	verified := &verifiedEvidence{
		raw:            append(json.RawMessage(nil), raw...),
		appraisalInput: append(json.RawMessage(nil), parsed.Evidences...),
		reports:        make([][]byte, 0, len(entries)),
		identities:     make([]string, 0, len(entries)),
		arches:         make([]string, 0, len(entries)),
	}
	for index, evidence := range entries {
		if evidence.Nonce != expectedNonce {
			return nil, fmt.Errorf("%s evidence[%d] nonce does not match the requested nonce", device, index)
		}
		report, err := base64.StdEncoding.DecodeString(evidence.Evidence)
		if err != nil {
			return nil, fmt.Errorf("decoding %s evidence[%d] report: %w", device, index, err)
		}
		if len(report) == 0 {
			return nil, fmt.Errorf("%s evidence[%d] report is empty", device, index)
		}
		certificate, err := base64.StdEncoding.DecodeString(evidence.Certificate)
		if err != nil {
			return nil, fmt.Errorf("decoding %s evidence[%d] certificate: %w", device, index, err)
		}
		if len(certificate) == 0 {
			return nil, fmt.Errorf("%s evidence[%d] certificate is empty", device, index)
		}
		identity := certificateIdentity(certificate)
		verified.reports = append(verified.reports, report)
		verified.identities = append(verified.identities, identity)
		verified.arches = append(verified.arches, strings.ToUpper(evidence.Arch))
	}
	normalizedIdentities, err := sortedUniqueIdentities(device+" evidence", verified.identities)
	if err != nil {
		return nil, err
	}
	verified.identities = normalizedIdentities
	return verified, nil
}

func appraiseEvidence(device string, nonce [32]byte, raw json.RawMessage) error {
	if err := os.MkdirAll(gpuEvidenceTempDir, 0755); err != nil {
		return fmt.Errorf("creating GPU evidence directory: %w", err)
	}
	file, err := os.CreateTemp(gpuEvidenceTempDir, "nvattest-evidence-*.json")
	if err != nil {
		return fmt.Errorf("creating %s evidence file: %w", device, err)
	}
	path := file.Name()
	defer file.Close()
	defer func() {
		if path != "" {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("writing %s evidence file: %w", device, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewinding %s evidence file: %w", device, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("unlinking %s evidence file: %w", device, err)
	}
	path = ""

	args := []string{
		"attest",
		"--device", device,
		"--verifier", "local",
		"--nonce", hex.EncodeToString(nonce[:]),
		"--format", "json",
	}
	if device == "gpu" {
		args = append(args, "--gpu-evidence-source", "file", "--gpu-evidence-file", "/proc/self/fd/3")
	} else if device == "nvswitch" {
		args = append(args, "--nvswitch-evidence-source", "file", "--nvswitch-evidence-file", "/proc/self/fd/3")
	} else {
		return fmt.Errorf("unsupported nvattest device %q", device)
	}

	ctx, cancel := context.WithTimeout(context.Background(), nvattestTimeout)
	defer cancel()
	cmd := commandContext(ctx, "nvattest", args...)
	cmd.ExtraFiles = []*os.File{file}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nvattest %s appraisal timed out after %s", device, nvattestTimeout)
		}
		return fmt.Errorf("nvattest %s appraisal failed: %w: %s", device, err, strings.TrimSpace(stderr.String()))
	}
	var result nvattestAppraisalOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return fmt.Errorf("parsing nvattest %s appraisal: %w", device, err)
	}
	if result.ResultCode != 0 {
		return fmt.Errorf("nvattest %s appraisal failed: %s (code %d)", device, result.ResultMessage, result.ResultCode)
	}
	return nil
}

func certificateIdentity(certificate []byte) string {
	digest := sha256.Sum256(certificate)
	return hex.EncodeToString(digest[:])
}

func sortedUniqueIdentities(source string, identities []string) ([]string, error) {
	normalized := slices.Clone(identities)
	slices.Sort(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index] == normalized[index-1] {
			return nil, fmt.Errorf("%s contains duplicate device identity %s", source, normalized[index])
		}
	}
	return normalized, nil
}

func liveGPUIdentities() ([]string, error) {
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("DeviceGetCount: %s", nvml.ErrorString(ret))
	}
	identities := make([]string, 0, count)
	for index := 0; index < count; index++ {
		device, ret := nvml.DeviceGetHandleByIndex(index)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("DeviceGetHandleByIndex(%d): %s", index, nvml.ErrorString(ret))
		}
		certificate, ret := device.GetConfComputeGpuCertificate()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GetConfComputeGpuCertificate(%d): %s", index, nvml.ErrorString(ret))
		}
		if certificate.AttestationCertChainSize == 0 || certificate.AttestationCertChainSize > uint32(len(certificate.AttestationCertChain)) {
			return nil, fmt.Errorf("GPU %d returned invalid attestation certificate size %d", index, certificate.AttestationCertChainSize)
		}
		identity := certificateIdentity(certificate.AttestationCertChain[:certificate.AttestationCertChainSize])
		identities = append(identities, identity)
	}
	return sortedUniqueIdentities("live GPU set", identities)
}

func sameIdentities(expected, actual []string) bool {
	return slices.Equal(expected, actual)
}

func identitySetDifference(expected, actual []string) (missing, unexpected []string) {
	actualSet := make(map[string]struct{}, len(actual))
	for _, identity := range actual {
		actualSet[identity] = struct{}{}
	}
	for _, identity := range expected {
		if _, exists := actualSet[identity]; !exists {
			missing = append(missing, identity)
		}
	}
	expectedSet := make(map[string]struct{}, len(expected))
	for _, identity := range expected {
		expectedSet[identity] = struct{}{}
	}
	for _, identity := range actual {
		if _, exists := expectedSet[identity]; !exists {
			unexpected = append(unexpected, identity)
		}
	}
	return missing, unexpected
}

func setGPUReadyStateWithRetry(state uint32) error {
	var failures []error
	for attempt := 1; attempt <= gpuReadyStateAttempts; attempt++ {
		ret := setGPUReadyStateValue(state)
		if ret == nvml.SUCCESS {
			return nil
		}
		failures = append(failures, fmt.Errorf("attempt %d: %s", attempt, nvml.ErrorString(ret)))
		if attempt < gpuReadyStateAttempts {
			time.Sleep(gpuReadyStateRetryBackoff)
		}
	}
	return errors.Join(failures...)
}

func withNVML(operation func() error) error {
	ret := initializeNVML()
	if ret != nvml.SUCCESS {
		return fmt.Errorf("nvml.Init: %s", nvml.ErrorString(ret))
	}
	defer shutdownNVML()
	return operation()
}

func rollbackGPUReadiness(cause error) error {
	if err := setGPUReadyStateWithRetry(nvml.CC_ACCEPTING_CLIENT_REQUESTS_FALSE); err != nil {
		return errors.Join(cause, fmt.Errorf("disabling GPU readiness after identity verification failure: %w", err))
	}
	return cause
}

func enableGPUsForIdentities(expected []string) error {
	return withNVML(func() error {
		before, err := snapshotLiveGPUIdentities()
		if err != nil {
			return err
		}
		if !sameIdentities(expected, before) {
			missing, unexpected := identitySetDifference(expected, before)
			return fmt.Errorf("live GPU identities changed before readiness: missing=%v unexpected=%v", missing, unexpected)
		}
		if err := setGPUReadyStateWithRetry(nvml.CC_ACCEPTING_CLIENT_REQUESTS_TRUE); err != nil {
			return fmt.Errorf("enabling GPU readiness: %w", err)
		}
		after, err := snapshotLiveGPUIdentities()
		if err != nil {
			return rollbackGPUReadiness(fmt.Errorf("checking GPU identities after readiness: %w", err))
		}
		if !sameIdentities(expected, after) {
			missing, unexpected := identitySetDifference(expected, after)
			return rollbackGPUReadiness(fmt.Errorf("live GPU identities changed during readiness: missing=%v unexpected=%v", missing, unexpected))
		}
		log.Printf("GPU ready state set to true for %d verified device(s)", len(expected))
		return nil
	})
}

func setGPUReadyState(accepting bool) error {
	return withNVML(func() error {
		var state uint32 = nvml.CC_ACCEPTING_CLIENT_REQUESTS_FALSE
		if accepting {
			state = nvml.CC_ACCEPTING_CLIENT_REQUESTS_TRUE
		}

		if err := setGPUReadyStateWithRetry(state); err != nil {
			return fmt.Errorf("setting GPU ready state to %v: %w", accepting, err)
		}
		log.Printf("GPU ready state set to %v", accepting)
		return nil
	})
}

// GPURawEvidence holds the raw nvattest collect-evidence JSON output.
// Each device's evidence contains hardware-signed SPDM reports and cert chains.
type GPURawEvidence struct {
	GPU    json.RawMessage `json:"gpu,omitempty"`
	Switch json.RawMessage `json:"nvswitch,omitempty"`
}

// dummyGPUEvidence returns mock GPU evidence matching the nvattest JSON format.
func dummyGPUEvidence(gpuCount int) *GPURawEvidence {
	gpuRaw := dummyEvidenceJSON(gpuCount)
	evidence := &GPURawEvidence{GPU: json.RawMessage(gpuRaw)}

	if gpuCount > 1 {
		switchRaw := dummyEvidenceJSON(4)
		evidence.Switch = json.RawMessage(switchRaw)
	}
	return evidence
}

func dummyEvidenceJSON(count int) []byte {
	entries := make([]nvattestEvidenceEntry, count)
	for index := range entries {
		entries[index].Arch = "DUMMY"
	}
	encodedEntries, _ := json.Marshal(entries)
	encodedOutput, _ := json.Marshal(nvattestEvidenceOutput{
		Evidences:     encodedEntries,
		ResultCode:    0,
		ResultMessage: "dummy-attestation",
	})
	return encodedOutput
}

func multiGPUArchitecture(arches []string) (string, error) {
	architecture := arches[0]
	for _, candidate := range arches[1:] {
		if candidate != architecture {
			return "", fmt.Errorf("GPU evidence contains mixed architectures %q and %q", architecture, candidate)
		}
	}
	return architecture, nil
}

// verifyGPUAttestation appraises one nonced evidence transaction and binds
// topology validation and readiness to the identities in that transaction.
func verifyGPUAttestation(expectedGPUs int) (*GPURawEvidence, error) {
	ok := false
	defer func() {
		if !ok {
			if err := disableGPUs(); err != nil {
				log.Printf("WARNING: failed to disable GPU ready state: %v", err)
			}
		}
	}()

	nonce, err := generateGPUAttestationNonce()
	if err != nil {
		return nil, err
	}

	log.Println("Collecting and appraising GPU evidence")
	gpuEvidence, err := collectAndAppraiseEvidence("gpu", nonce)
	if err != nil {
		return nil, fmt.Errorf("verifying GPU evidence: %w", err)
	}
	if len(gpuEvidence.reports) != expectedGPUs {
		return nil, fmt.Errorf("expected %d GPU reports, got %d", expectedGPUs, len(gpuEvidence.reports))
	}
	evidence := &GPURawEvidence{GPU: gpuEvidence.raw}

	if expectedGPUs > 1 {
		architecture, err := multiGPUArchitecture(gpuEvidence.arches)
		if err != nil {
			return nil, err
		}
		switch architecture {
		case gpuattestation.GPUArchBlackwell:
			log.Printf("HGX Blackwell MPT: no in-guest NVSwitch evidence")
		case gpuattestation.GPUArchHopper:
			log.Println("Collecting and appraising NVSwitch evidence for topology validation")
			switchEvidence, err := collectAndAppraiseEvidence("nvswitch", nonce)
			if err != nil {
				return nil, fmt.Errorf("verifying switch evidence: %w", err)
			}
			evidence.Switch = switchEvidence.raw
			log.Printf("Validating Hopper PPCIe topology (%d GPUs, %d switches)", expectedGPUs, hopperSwitchCount)
			if err := validateTopology(gpuEvidence.reports, switchEvidence.reports, expectedGPUs, hopperSwitchCount); err != nil {
				return nil, fmt.Errorf("topology validation failed: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported multi-GPU architecture %q", architecture)
		}
	}

	if err := enableVerifiedGPUs(gpuEvidence.identities); err != nil {
		return nil, fmt.Errorf("enabling verified GPUs: %w", err)
	}

	ok = true
	log.Println("GPU attestation verified")
	return evidence, nil
}
