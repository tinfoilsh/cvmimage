package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"

	"tinfoil/internal/attestation"
	"tinfoil/internal/attestationmaterial"
	shimconfig "tinfoil/internal/config"
	tlsutil "tinfoil/internal/tls"
)

func fetchCPUAttestation(domain string, shimCfg *shimconfig.Config) (json.RawMessage, error) {
	if domain == "localhost" || shimCfg.DummyAttestation {
		return nil, nil
	}
	nonce, err := envelope.RandomNonce()
	if err != nil {
		return nil, fmt.Errorf("generating collateral nonce: %w", err)
	}
	return attestation.BuildAttestation(nil, nonce, nil, wire.Response{Format: wire.FormatV3})
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

func writeCollateralRequest(path string, document json.RawMessage, metadata shimconfig.Metadata, configPath string) (attestationmaterial.Request, error) {
	if len(document) == 0 {
		return attestationmaterial.Request{}, nil
	}
	request := attestationmaterial.Request{
		Version: attestationmaterial.RequestVersionDocument, Document: document,
		Profile: wire.FormatV3, Repo: metadata.Repo, Tag: metadata.Tag, Digest: metadata.Digest,
	}
	switch metadata.ConfigSource {
	case "":
	case shimconfig.SourceLocal:
		request.Repo, request.Tag, request.Digest = "", "", ""
		var err error
		request.Config, err = os.ReadFile(configPath)
		if err != nil {
			return attestationmaterial.Request{}, fmt.Errorf("reading local config: %w", err)
		}
	default:
		return attestationmaterial.Request{}, fmt.Errorf("unsupported config source %q", metadata.ConfigSource)
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
