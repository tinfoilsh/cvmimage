package main

import (
	"encoding/json"
	"fmt"
	"os"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"

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
	if request.Platform != attestation.PlatformDummy {
		switch request.Profile {
		case "":
			if request.Repo == "" || request.Digest != "" || request.Runtime != "" {
				return wire.Request{}, fmt.Errorf("legacy collateral request requires a repository")
			}
		case wire.FormatV3:
			if request.Runtime != "" {
				if request.Repo != "" || request.Tag != "" || request.Digest != "" {
					return wire.Request{}, fmt.Errorf("runtime and registry config references are mutually exclusive")
				}
			} else if request.Repo == "" || request.Tag == "" || request.Digest == "" {
				return wire.Request{}, fmt.Errorf("registry collateral request requires a project, revision, and config digest")
			}
		default:
			return wire.Request{}, fmt.Errorf("unsupported collateral request profile %q", request.Profile)
		}
	}
	return request, nil
}
