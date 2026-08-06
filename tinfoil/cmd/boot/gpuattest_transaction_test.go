package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"tinfoil/internal/nvml"
)

func fixedGPUAttestationNonce() [32]byte {
	var nonce [32]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	return nonce
}

func installFakeNvattest(t *testing.T, appraisalCode int) (string, string) {
	t.Helper()
	directory := t.TempDir()
	callsPath := filepath.Join(directory, "calls")
	appraisedPath := filepath.Join(directory, "appraised")
	noncePath := filepath.Join(directory, "nonce")
	scriptPath := filepath.Join(directory, "nvattest")
	script := `#!/bin/sh
set -eu
printf '%s\n' "$1" >> "$NVATTEST_CALLS"
command="$1"
shift
nonce=""
evidence_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --nonce) nonce="$2"; shift 2 ;;
    --gpu-evidence-file|--nvswitch-evidence-file) evidence_file="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$command" = "collect-evidence" ]; then
  printf '%s' "$nonce" > "$NVATTEST_NONCE"
  printf '{"evidences":[{"arch":"HOPPER","certificate":"Y2VydGlmaWNhdGU=","evidence":"AQID","nonce":"%s"}],"result_code":0,"result_message":"ok"}\n' "$nonce"
  exit 0
fi
if [ -f "$NVATTEST_NONCE" ]; then
  test "$nonce" = "$(cat "$NVATTEST_NONCE")"
fi
cat "$evidence_file" > "$NVATTEST_APPRAISED"
printf '{"result_code":%s,"result_message":"appraisal"}\n' "$NVATTEST_APPRAISAL_CODE"
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+":"+os.Getenv("PATH"))
	t.Setenv("NVATTEST_CALLS", callsPath)
	t.Setenv("NVATTEST_APPRAISED", appraisedPath)
	t.Setenv("NVATTEST_NONCE", noncePath)
	t.Setenv("NVATTEST_APPRAISAL_CODE", fmt.Sprintf("%d", appraisalCode))
	oldTempDir := gpuEvidenceTempDir
	gpuEvidenceTempDir = directory
	t.Cleanup(func() { gpuEvidenceTempDir = oldTempDir })
	return callsPath, appraisedPath
}

func TestCollectAndAppraiseEvidenceUsesOneNoncedTransaction(t *testing.T) {
	callsPath, appraisedPath := installFakeNvattest(t, 0)
	nonce := fixedGPUAttestationNonce()

	verified, err := collectAndAppraiseEvidence("gpu", nonce)
	if err != nil {
		t.Fatalf("collectAndAppraiseEvidence: %v", err)
	}
	if len(verified.reports) != 1 || !slices.Equal(verified.reports[0], []byte{1, 2, 3}) {
		t.Fatalf("reports = %#v", verified.reports)
	}
	wantIdentity := sha256.Sum256([]byte("certificate"))
	if len(verified.identities) != 1 || verified.identities[0] != hex.EncodeToString(wantIdentity[:]) {
		t.Fatalf("identities = %#v", verified.identities)
	}
	appraised, err := os.ReadFile(appraisedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(appraised) != string(verified.appraisalInput) {
		t.Fatal("appraiser did not consume the exact collected evidence bytes")
	}
	calls, err := os.ReadFile(callsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(calls)); !slices.Equal(got, []string{"collect-evidence", "attest"}) {
		t.Fatalf("nvattest calls = %#v", got)
	}
}

func TestParseEvidenceRejectsWrongNonce(t *testing.T) {
	nonce := fixedGPUAttestationNonce()
	entries, err := json.Marshal([]nvattestEvidenceEntry{{
		Arch:        "HOPPER",
		Certificate: base64.StdEncoding.EncodeToString([]byte("certificate")),
		Evidence:    base64.StdEncoding.EncodeToString([]byte("report")),
		Nonce:       strings.Repeat("00", 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(nvattestEvidenceOutput{Evidences: entries})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseEvidence("gpu", nonce, raw); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("parseEvidence error = %v", err)
	}
}

func TestParseEvidenceRejectsDuplicateIdentity(t *testing.T) {
	nonce := fixedGPUAttestationNonce()
	nonceHex := hex.EncodeToString(nonce[:])
	entry := nvattestEvidenceEntry{
		Arch:        "HOPPER",
		Certificate: base64.StdEncoding.EncodeToString([]byte("certificate")),
		Evidence:    base64.StdEncoding.EncodeToString([]byte("report")),
		Nonce:       nonceHex,
	}
	entries, err := json.Marshal([]nvattestEvidenceEntry{entry, entry})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(nvattestEvidenceOutput{Evidences: entries})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseEvidence("gpu", nonce, raw); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("parseEvidence error = %v", err)
	}
}

func TestAppraiseEvidenceRejectsFailedResult(t *testing.T) {
	installFakeNvattest(t, 7)
	nonce := fixedGPUAttestationNonce()
	raw := json.RawMessage(`{"evidences":[]}`)
	if err := appraiseEvidence("gpu", nonce, raw); err == nil || !strings.Contains(err.Error(), "code 7") {
		t.Fatalf("appraiseEvidence error = %v", err)
	}
}

func TestVerifyGPUAttestationBindsReadinessToEvidenceIdentity(t *testing.T) {
	installFakeNvattest(t, 0)
	nonce := fixedGPUAttestationNonce()
	oldNonceGenerator := generateGPUAttestationNonce
	oldEnable := enableVerifiedGPUs
	oldDisable := disableGPUs
	t.Cleanup(func() {
		generateGPUAttestationNonce = oldNonceGenerator
		enableVerifiedGPUs = oldEnable
		disableGPUs = oldDisable
	})
	generateGPUAttestationNonce = func() ([32]byte, error) { return nonce, nil }
	disableGPUs = func() error { return nil }
	var readinessIdentities []string
	enableVerifiedGPUs = func(identities []string) error {
		readinessIdentities = slices.Clone(identities)
		return nil
	}

	if _, err := verifyGPUAttestation(1); err != nil {
		t.Fatalf("verifyGPUAttestation: %v", err)
	}
	wantIdentity := sha256.Sum256([]byte("certificate"))
	if !slices.Equal(readinessIdentities, []string{hex.EncodeToString(wantIdentity[:])}) {
		t.Fatalf("readiness identities = %#v", readinessIdentities)
	}
}

func TestVerifyGPUAttestationFailsWhenIdentityGateDetectsReplacement(t *testing.T) {
	installFakeNvattest(t, 0)
	nonce := fixedGPUAttestationNonce()
	oldNonceGenerator := generateGPUAttestationNonce
	oldEnable := enableVerifiedGPUs
	oldDisable := disableGPUs
	t.Cleanup(func() {
		generateGPUAttestationNonce = oldNonceGenerator
		enableVerifiedGPUs = oldEnable
		disableGPUs = oldDisable
	})
	generateGPUAttestationNonce = func() ([32]byte, error) { return nonce, nil }
	enableVerifiedGPUs = func([]string) error { return errors.New("live GPU identities changed before readiness") }
	disabled := false
	disableGPUs = func() error {
		disabled = true
		return nil
	}

	if _, err := verifyGPUAttestation(1); err == nil || !strings.Contains(err.Error(), "identities changed") {
		t.Fatalf("verifyGPUAttestation error = %v", err)
	}
	if !disabled {
		t.Fatal("failed verification did not force GPU readiness off")
	}
}

func TestIdentitySetComparisonDetectsReplacement(t *testing.T) {
	if sameIdentities([]string{"a", "b"}, []string{"a", "c"}) {
		t.Fatal("replacement passed identity comparison")
	}
}

func TestIdentitySetDifferenceReportsReplacement(t *testing.T) {
	missing, unexpected := identitySetDifference([]string{"a", "b"}, []string{"b", "c"})
	if !slices.Equal(missing, []string{"a"}) || !slices.Equal(unexpected, []string{"c"}) {
		t.Fatalf("missing=%v unexpected=%v", missing, unexpected)
	}
}

func TestEnableGPUsForIdentitiesRollsBackMidTransitionReplacement(t *testing.T) {
	oldInitialize := initializeNVML
	oldShutdown := shutdownNVML
	oldSnapshot := snapshotLiveGPUIdentities
	oldSetReady := setGPUReadyStateValue
	t.Cleanup(func() {
		initializeNVML = oldInitialize
		shutdownNVML = oldShutdown
		snapshotLiveGPUIdentities = oldSnapshot
		setGPUReadyStateValue = oldSetReady
	})

	initializeNVML = func() nvml.Return { return nvml.SUCCESS }
	shutdownCalled := false
	shutdownNVML = func() nvml.Return {
		shutdownCalled = true
		return nvml.SUCCESS
	}
	snapshots := [][]string{{"verified"}, {"replacement"}}
	snapshotLiveGPUIdentities = func() ([]string, error) {
		identity := snapshots[0]
		snapshots = snapshots[1:]
		return identity, nil
	}
	var states []uint32
	setGPUReadyStateValue = func(state uint32) nvml.Return {
		states = append(states, state)
		return nvml.SUCCESS
	}

	err := enableGPUsForIdentities([]string{"verified"})
	if err == nil || !strings.Contains(err.Error(), "unexpected=[replacement]") {
		t.Fatalf("enableGPUsForIdentities error = %v", err)
	}
	wantStates := []uint32{
		nvml.CC_ACCEPTING_CLIENT_REQUESTS_TRUE,
		nvml.CC_ACCEPTING_CLIENT_REQUESTS_FALSE,
	}
	if !slices.Equal(states, wantStates) {
		t.Fatalf("ready states = %v, want %v", states, wantStates)
	}
	if !shutdownCalled {
		t.Fatal("NVML was not shut down")
	}
}
