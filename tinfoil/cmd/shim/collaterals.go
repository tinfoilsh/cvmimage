package main

import (
	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestationmaterial"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

func newCollateralSource(att *legacy.Document, config *shimconfig.Config, external *shimconfig.ExternalConfig) (collateralSource, error) {
	request, ok, err := collateralRequest(att, external)
	if err != nil || !ok {
		return nil, err
	}
	client, err := attestationmaterial.NewClient(config.ATC, nil)
	if err != nil {
		return nil, err
	}
	return attestationmaterial.NewCache(request, client), nil
}

func collateralRequest(att *legacy.Document, external *shimconfig.ExternalConfig) (wire.Request, bool, error) {
	return attestationmaterial.Request(att, external)
}
