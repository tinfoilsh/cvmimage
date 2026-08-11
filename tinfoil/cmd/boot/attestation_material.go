package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// fetchAttestationMaterial asks the Tinfoil collaterals service for
// the v3 collateral array (hardware endorsement + code + platform reference
// values). The code repo comes from the deployment metadata (`repo`,
// written by tinfoild). A launch without one gets an empty collateral set
// — never a guessed repo — so its documents fail verification with a
// clear "no collateral" instead of carrying provenance for code the
// enclave does not run.
func fetchAttestationMaterial(cpuAtt *CPUAttestation, shimCfg *shimconfig.Config, ext *shimconfig.ExternalConfig) error {
	if cpuAtt == nil {
		return fmt.Errorf("cpu attestation is nil")
	}
	if shimCfg.DummyAttestation || cpuAtt.Platform == "dummy" {
		log.Printf("Skipping collaterals fetch for platform=%s dummy=%t", cpuAtt.Platform, shimCfg.DummyAttestation)
		return writeEmptyAttestationMaterial()
	}
	var repo, tag string
	if ext != nil {
		repo, tag = ext.Metadata.Repo, ext.Metadata.Tag
	}
	if repo == "" {
		log.Printf("No code repo in deployment metadata; writing empty attestation material")
		return writeEmptyAttestationMaterial()
	}

	atc, err := url.Parse(shimCfg.ATC)
	if err != nil {
		return fmt.Errorf("parsing ATC URL: %w", err)
	}
	endpoint := atc.JoinPath("attestation-collaterals").String()
	body, err := json.Marshal(wire.Request{
		Repo:        repo,
		Tag:         tag,
		Platform:    cpuAtt.Platform,
		QuoteBase64: base64.StdEncoding.EncodeToString(cpuAtt.RawReport),
	})
	if err != nil {
		return fmt.Errorf("marshaling collaterals request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return fmt.Errorf("reading collaterals response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: %s: %s", endpoint, resp.Status, string(respBody))
	}

	// Sanity-check the shape before persisting so the shim never loads
	// something it cannot serve.
	var material wire.Response
	if err := json.Unmarshal(respBody, &material); err != nil {
		return fmt.Errorf("parsing collaterals response: %w", err)
	}
	if material.Format != wire.FormatV2 {
		return fmt.Errorf("unexpected collaterals format %q", material.Format)
	}

	if err := os.WriteFile(boot.AttestationMaterialPath, respBody, 0o600); err != nil {
		return fmt.Errorf("writing attestation material: %w", err)
	}
	log.Printf("Attestation material written to %s (%d collateral entries)", boot.AttestationMaterialPath, len(material.Collateral))
	return nil
}

// writeEmptyAttestationMaterial persists an empty collateral set for dummy
// (non-hardware) launches; the shim then serves v3 documents without
// collateral, which verifiers reject — fail closed, but boot proceeds.
func writeEmptyAttestationMaterial() error {
	data, err := json.Marshal(wire.Response{
		Format:     wire.FormatV2,
		Collateral: nil,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(boot.AttestationMaterialPath, data, 0o600)
}
