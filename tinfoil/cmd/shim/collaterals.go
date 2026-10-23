package main

import (
	"encoding/json"
	"fmt"
	"os"

	"tinfoil/internal/attestationmaterial"
)

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
	return request, nil
}
