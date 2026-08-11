package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestation"
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
	if att.Format == legacy.DummyV2 || external == nil || external.Metadata.Repo == "" {
		return wire.Request{}, false, nil
	}

	var platform string
	switch att.Format {
	case legacy.SevGuestV2:
		platform = attestation.PlatformSEVSNP
	case legacy.TdxGuestV2:
		platform = attestation.PlatformTDX
	default:
		return wire.Request{}, false, fmt.Errorf("unsupported attestation format %q", att.Format)
	}
	compressed, err := base64.StdEncoding.DecodeString(att.Body)
	if err != nil {
		return wire.Request{}, false, fmt.Errorf("decoding attestation report: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return wire.Request{}, false, fmt.Errorf("opening attestation report: %w", err)
	}
	quote, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil {
		return wire.Request{}, false, fmt.Errorf("reading attestation report: %w", err)
	}
	if closeErr != nil {
		return wire.Request{}, false, fmt.Errorf("closing attestation report: %w", closeErr)
	}
	return wire.Request{
		Repo:        external.Metadata.Repo,
		Tag:         external.Metadata.Tag,
		Platform:    platform,
		QuoteBase64: base64.StdEncoding.EncodeToString(quote),
	}, true, nil
}
