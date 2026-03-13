package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	"tinfoil/internal/attestation"
	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	tlsutil "tinfoil/internal/tls"
)

type CPUAttestation struct {
	RawReport []byte
	Platform  string
	V2Doc     *verifier.Document
}

func fetchCPUAttestation(id *NodeIdentity, shimCfg *shimconfig.Config) (*CPUAttestation, error) {
	var hpkeKey [32]byte
	copy(hpkeKey[:], id.HPKEKeyBytes)

	aBody := attestation.BodyV2{
		TLSKeyFP: tlsutil.KeyFPBytes(id.TLSKey.Public().(*ecdsa.PublicKey)),
		HPKEKey:  hpkeKey,
	}
	log.Printf("Attestation body: tls_fp=%x hpke=%x", aBody.TLSKeyFP, aBody.HPKEKey)
	userData := aBody.Marshal()

	if id.Domain == "localhost" || shimCfg.DummyAttestation {
		log.Println("Using dummy attestation report")
		doc := attestation.DummyReport(userData)
		if err := writeAttestationDoc(doc); err != nil {
			return nil, err
		}
		return &CPUAttestation{
			RawReport: userData[:],
			Platform:  "dummy",
			V2Doc:     doc,
		}, nil
	}

	log.Println("Fetching hardware attestation report")
	rawReport, platform, err := attestation.Report(userData)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation report: %w", err)
	}

	v2Doc, err := attestation.V2Document(rawReport, platform)
	if err != nil {
		return nil, fmt.Errorf("building V2 document: %w", err)
	}

	if err := writeAttestationDoc(v2Doc); err != nil {
		return nil, err
	}

	return &CPUAttestation{
		RawReport: rawReport,
		Platform:  platform,
		V2Doc:     v2Doc,
	}, nil
}

func writeAttestationDoc(att *verifier.Document) error {
	data, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling attestation document: %w", err)
	}
	if err := os.WriteFile(boot.AttestationPath, data, 0644); err != nil {
		return fmt.Errorf("writing attestation document: %w", err)
	}
	log.Println("V2 attestation document written to ramdisk")
	return nil
}

const attestationV3Format = "https://tinfoil.sh/predicate/attestation/v3"

type attestationV3 struct {
	Format   string          `json:"format"`
	CPU      attestationCPU  `json:"cpu"`
	GPU      json.RawMessage `json:"gpu,omitempty"`
	NVSwitch json.RawMessage `json:"nvswitch,omitempty"`
}

type attestationCPU struct {
	Platform string `json:"platform"`
	Report   string `json:"report"`
}

func writeAttestationV3(cpuAtt *CPUAttestation, gpuEvidence *GPURawEvidence) error {
	v3 := attestationV3{
		Format: attestationV3Format,
		CPU: attestationCPU{
			Platform: cpuAtt.Platform,
			Report:   base64.StdEncoding.EncodeToString(cpuAtt.RawReport),
		},
	}

	if gpuEvidence != nil {
		v3.GPU = gpuEvidence.GPU
		v3.NVSwitch = gpuEvidence.Switch
	}

	data, err := json.Marshal(v3)
	if err != nil {
		return fmt.Errorf("marshaling V3 attestation: %w", err)
	}
	if err := os.WriteFile(boot.AttestationV3Path, data, 0644); err != nil {
		return fmt.Errorf("writing V3 attestation: %w", err)
	}
	log.Println("V3 attestation document written to ramdisk")
	return nil
}
