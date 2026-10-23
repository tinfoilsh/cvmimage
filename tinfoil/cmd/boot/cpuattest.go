package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"

	envelope "github.com/tinfoilsh/tinfoil-go/document"

	verifier "tinfoil/internal/legacy"

	"tinfoil/internal/attestation"
	"tinfoil/internal/attestationmaterial"
	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	tlsutil "tinfoil/internal/tls"
)

type CPUAttestation struct {
	Document json.RawMessage
	V2Doc    *verifier.Document
}

func fetchCPUAttestation(id *NodeIdentity, shimCfg *shimconfig.Config) (*CPUAttestation, error) {
	aBody := id.attestationBody()
	log.Printf("Attestation body: tls_fp=%x hpke=%x", aBody.TLSKeyFP, aBody.HPKEKey)
	userData := aBody.V2ReportData()

	if id.Domain == "localhost" || shimCfg.DummyAttestation {
		log.Println("Using dummy attestation report")
		doc := attestation.DummyReport(userData)
		if err := writeAttestationDoc(doc); err != nil {
			return nil, err
		}
		return &CPUAttestation{
			V2Doc: doc,
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
	nonce := make([]byte, envelope.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating collateral nonce: %w", err)
	}
	document, err := attestation.BuildAttestation(nil, nonce, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("building collateral document: %w", err)
	}

	return &CPUAttestation{
		Document: document,
		V2Doc:    v2Doc,
	}, nil
}

func (id *NodeIdentity) attestationBody() attestation.Identity {
	var hpkeKey [32]byte
	copy(hpkeKey[:], id.HPKEKeyBytes)
	return attestation.Identity{
		TLSKeyFP: tlsutil.KeyFPBytes(id.TLSKey.Public().(*ecdsa.PublicKey)),
		HPKEKey:  hpkeKey,
		Workload: id.WorkloadKeys,
	}
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

func writeCollateralRequest(path string, document json.RawMessage, metadata shimconfig.Metadata) (attestationmaterial.Request, error) {
	if len(document) == 0 {
		return attestationmaterial.Request{}, nil
	}
	request := attestationmaterial.Request{
		Version:  attestationmaterial.RequestVersionDocument,
		Document: document,
		Repo:     metadata.Repo,
		Tag:      metadata.Tag,
	}
	if err := request.Validate(); err != nil {
		return attestationmaterial.Request{}, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return attestationmaterial.Request{}, fmt.Errorf("marshaling collateral request: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return attestationmaterial.Request{}, fmt.Errorf("writing collateral request: %w", err)
	}
	return request, nil
}
