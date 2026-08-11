package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestationmaterial"
	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// fetchAttestationMaterial gets the initial collateral bundle and persists
// the request descriptor so the long-running shim can refresh the same
// hardware- and release-specific collateral without changing its trust role.
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

	request := wire.Request{
		Repo:        repo,
		Tag:         tag,
		Platform:    cpuAtt.Platform,
		QuoteBase64: base64.StdEncoding.EncodeToString(cpuAtt.RawReport),
	}
	client, err := attestationmaterial.NewClient(shimCfg.ATC, nil)
	if err != nil {
		return err
	}
	response, err := client.Fetch(context.Background(), request)
	if err != nil {
		return err
	}
	if err := attestationmaterial.WriteJSON(boot.AttestationMaterialRequestPath, request); err != nil {
		return fmt.Errorf("writing attestation material request: %w", err)
	}
	if err := attestationmaterial.WriteJSON(boot.AttestationMaterialPath, response); err != nil {
		return fmt.Errorf("writing attestation material: %w", err)
	}
	log.Printf("Attestation material written to %s (%d collateral entries, expires %s)", boot.AttestationMaterialPath, len(response.Collateral), response.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	return nil
}

func writeEmptyAttestationMaterial() error {
	if err := attestationmaterial.WriteJSON(boot.AttestationMaterialRequestPath, wire.Request{}); err != nil {
		return err
	}
	return attestationmaterial.WriteJSON(boot.AttestationMaterialPath, wire.Response{
		Format:     wire.FormatV2,
		Collateral: nil,
	})
}
