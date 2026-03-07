package main

import (
	"crypto/ecdsa"
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

func fetchCPUAttestation(id *NodeIdentity, shimCfg *shimconfig.Config) (*verifier.Document, error) {
	var hpkeKey [32]byte
	copy(hpkeKey[:], id.HPKEKeyBytes)

	aBody := attestation.BodyV2{
		TLSKeyFP: tlsutil.KeyFPBytes(id.TLSKey.Public().(*ecdsa.PublicKey)),
		HPKEKey:  hpkeKey,
	}
	log.Printf("Attestation body: tls_fp=%x hpke=%x", aBody.TLSKeyFP, aBody.HPKEKey)
	userData := aBody.Marshal()

	var att *verifier.Document
	if id.Domain == "localhost" || shimCfg.DummyAttestation {
		log.Println("Using dummy attestation report")
		att = attestation.DummyReport(userData)
	} else {
		log.Println("Fetching hardware attestation report")
		var err error
		att, err = attestation.Report(userData)
		if err != nil {
			return nil, fmt.Errorf("fetching attestation report: %w", err)
		}
	}

	if err := writeAttestationDoc(att); err != nil {
		return nil, err
	}

	return att, nil
}

func writeAttestationDoc(att *verifier.Document) error {
	data, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling attestation document: %w", err)
	}
	if err := os.WriteFile(boot.AttestationPath, data, 0644); err != nil {
		return fmt.Errorf("writing attestation document: %w", err)
	}
	log.Println("Attestation document written to ramdisk")
	return nil
}
