package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"

	verifier "tinfoil/internal/legacy"

	"tinfoil/internal/attestation"
	shimconfig "tinfoil/internal/config"
	tlsutil "tinfoil/internal/tls"
)

type CPUAttestation struct {
	RawReport []byte
	Platform  string
	V2Doc     *verifier.Document
}

func fetchCPUAttestation(id *NodeIdentity, shimCfg *shimconfig.Config) (*CPUAttestation, error) {
	aBody := id.attestationBody()
	log.Printf("Attestation body: tls_fp=%x hpke=%x", aBody.TLSKeyFP, aBody.HPKEKey)
	userData := aBody.Marshal()

	if id.Domain == "localhost" || shimCfg.DummyAttestation {
		log.Println("Using dummy attestation report")
		doc := attestation.DummyReport(userData)
		return &CPUAttestation{
			RawReport: userData[:],
			Platform:  attestation.PlatformDummy,
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

	return &CPUAttestation{
		RawReport: rawReport,
		Platform:  platform,
		V2Doc:     v2Doc,
	}, nil
}

func (id *NodeIdentity) attestationBody() attestation.BodyV2 {
	var hpkeKey [32]byte
	copy(hpkeKey[:], id.HPKEKeyBytes)
	return attestation.BodyV2{
		TLSKeyFP: tlsutil.KeyFPBytes(id.TLSKey.Public().(*ecdsa.PublicKey)),
		HPKEKey:  hpkeKey,
		Workload: id.WorkloadKeys,
	}
}

func writeCollateralRequest(path string, cpuAtt *CPUAttestation, external *shimconfig.ExternalConfig) (wire.Request, error) {
	if cpuAtt == nil || len(cpuAtt.RawReport) == 0 || cpuAtt.Platform == "" {
		return wire.Request{}, fmt.Errorf("raw CPU attestation is required")
	}
	request := wire.Request{
		Platform:    cpuAtt.Platform,
		QuoteBase64: base64.StdEncoding.EncodeToString(cpuAtt.RawReport),
	}
	if external != nil {
		request.Repo = external.Metadata.Repo
		request.Tag = external.Metadata.Tag
		if ref := external.Metadata.Config; ref != nil {
			request.Profile = wire.FormatV3
			request.Config = &collateral.ConfigReference{Name: ref.Name, Digest: ref.Digest}
		}
		if ref := external.Metadata.Runtime; ref != nil {
			request.Runtime = &collateral.RuntimeReference{Repo: ref.Repo, Tag: ref.Tag, Digest: ref.Digest}
		}
	}
	data, err := json.Marshal(request)
	if err != nil {
		return wire.Request{}, fmt.Errorf("marshaling collateral request: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return wire.Request{}, fmt.Errorf("writing collateral request: %w", err)
	}
	return request, nil
}
