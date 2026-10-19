package main

import (
	"encoding/json"
	"fmt"
	"os"

	"tinfoil/internal/attestation"
	"tinfoil/internal/attestationmaterial"
	shimconfig "tinfoil/internal/config"
)

func newCollateralSource(request attestationmaterial.Request, config *shimconfig.Config) (collateralSource, error) {
	if request.Platform == attestation.PlatformDummy {
		return nil, nil
	}
	client, err := attestationmaterial.NewClient(config.ATC, nil)
	if err != nil {
		return nil, err
	}
	return attestationmaterial.NewCache(request, client), nil
}

func loadCollateralRequest(path string) (attestationmaterial.Request, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return attestationmaterial.Request{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var request attestationmaterial.Request
	if err := json.Unmarshal(data, &request); err != nil {
		return attestationmaterial.Request{}, fmt.Errorf("parsing collateral request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return attestationmaterial.Request{}, err
	}
	if request.Platform != attestation.PlatformDummy && request.Repo == "" {
		return attestationmaterial.Request{}, fmt.Errorf("collateral request is missing repo")
	}
	return request, nil
}
