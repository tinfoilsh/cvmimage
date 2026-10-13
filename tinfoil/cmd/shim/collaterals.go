package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"

	"tinfoil/internal/attestation"
	"tinfoil/internal/attestationmaterial"
	shimconfig "tinfoil/internal/config"
)

func newCollateralSource(request wire.Request, config *shimconfig.Config, configPath string) (collateralSource, error) {
	if request.Platform == attestation.PlatformDummy {
		return nil, nil
	}
	client, err := attestationmaterial.NewClient(config.ATC, nil)
	if err != nil {
		return nil, err
	}
	cache := attestationmaterial.NewCache(request, client)
	if request.Runtime == "" {
		return cache, nil
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading local config: %w", err)
	}
	encoded, err := json.Marshal(struct {
		Config []byte `json:"config_base64"`
	}{Config: data})
	if err != nil {
		return nil, err
	}
	return &localConfigCollateral{collateralSource: cache, config: encoded}, nil
}

type localConfigCollateral struct {
	collateralSource
	config []byte
}

func (s *localConfigCollateral) Current(ctx context.Context) (wire.Response, error) {
	response, err := s.collateralSource.Current(ctx)
	if err != nil {
		return wire.Response{}, err
	}
	response.Collateral = append(response.Collateral, collateral.Entry{
		ID: collateral.ConfigID, Role: collateral.RoleReferenceValues,
		Format: collateral.ConfigV1Format, Data: bytes.Clone(s.config),
	})
	return response, nil
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
