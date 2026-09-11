package boot

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestation"
	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	verifier "tinfoil/internal/legacy"
)

func writeAttestationDoc(att *verifier.Document) error {
	data, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling attestation document: %w", err)
	}
	if err := os.WriteFile(bootstate.AttestationPath, data, 0644); err != nil {
		return fmt.Errorf("writing attestation document: %w", err)
	}
	log.Println("V2 attestation document written to ramdisk")
	return nil
}

func writeCollateralRequest(path string, cpuAtt *attestation.CPU, external *shimconfig.ExternalConfig) (wire.Request, error) {
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

func writeTLSArtifacts(cert *tls.Certificate, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(bootstate.TLSDir, 0700); err != nil {
		return fmt.Errorf("creating TLS directory: %w", err)
	}

	var certPEM []byte
	for _, derCert := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})...)
	}
	if err := os.WriteFile(bootstate.TLSCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing TLS cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling TLS key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(bootstate.TLSKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing TLS key: %w", err)
	}

	log.Println("TLS certificate and key written to ramdisk")
	return nil
}

func publishConfig(inputs *inputs) error {
	if err := os.WriteFile(bootstate.ConfigPath, inputs.configSource, 0644); err != nil {
		return fmt.Errorf("writing config to ramdisk: %w", err)
	}
	if err := os.WriteFile(bootstate.ExternalConfigPath, inputs.externalSource, 0600); err != nil {
		return fmt.Errorf("writing external config: %w", err)
	}
	if err := shimconfig.WriteShim(bootstate.ShimConfigPath, inputs.config.ShimCfg); err != nil {
		return fmt.Errorf("writing shim config: %w", err)
	}
	return nil
}
