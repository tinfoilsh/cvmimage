package main

import (
	"encoding/json"
	"fmt"
	"os"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestation"
	"tinfoil/internal/attestationmaterial"
	shimconfig "tinfoil/internal/config"
)

func newCollateralSource(request wire.Request, config *shimconfig.Config) (collateralSource, error) {
	if request.Platform == attestation.PlatformDummy {
		return nil, nil
	}
	client, err := attestationmaterial.NewClient(config.ATC, nil)
	if err != nil {
		return nil, err
	}
	return attestationmaterial.NewCache(request, client), nil
}

func loadCollateralRequest(path string) (wire.Request, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return wire.Request{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var request wire.Request
	if err := json.Unmarshal(data, &request); err != nil {
		return wire.Request{}, fmt.Errorf("parsing collateral request: %w", err)
	}
	if request.Platform == "" {
		return wire.Request{}, fmt.Errorf("collateral request is missing platform")
	}
	if request.QuoteBase64 == "" {
		return wire.Request{}, fmt.Errorf("collateral request is missing quote_base64")
	}
	if request.Platform != attestation.PlatformDummy && request.Repo == "" {
		return wire.Request{}, fmt.Errorf("collateral request is missing repo")
	}
	return request, nil
}
