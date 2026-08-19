package attestationmaterial

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestation"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

const maxCPUQuoteBytes = 1 << 20

// Request extracts the raw CPU quote and authenticated artifact selectors ATC
// needs to assemble v3 collateral. Dummy reports have no collateral source.
func Request(att *legacy.Document, external *shimconfig.ExternalConfig) (wire.Request, bool, error) {
	if att == nil {
		return wire.Request{}, false, fmt.Errorf("attestation document is required")
	}
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
	defer reader.Close()
	quote, err := io.ReadAll(io.LimitReader(reader, maxCPUQuoteBytes+1))
	if err != nil {
		return wire.Request{}, false, fmt.Errorf("reading attestation report: %w", err)
	}
	if len(quote) > maxCPUQuoteBytes {
		return wire.Request{}, false, fmt.Errorf("attestation report exceeds %d bytes", maxCPUQuoteBytes)
	}
	return wire.Request{
		Repo:        external.Metadata.Repo,
		Tag:         external.Metadata.Tag,
		Platform:    platform,
		QuoteBase64: base64.StdEncoding.EncodeToString(quote),
	}, true, nil
}
