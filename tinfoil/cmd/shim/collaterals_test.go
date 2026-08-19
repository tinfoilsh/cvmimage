package main

import (
	"encoding/base64"
	"testing"

	"tinfoil/internal/attestation"
	"tinfoil/internal/attestationmaterial"
	"tinfoil/internal/config"
)

func TestCollateralRequestFromAttestation(t *testing.T) {
	quote := []byte("hardware quote")
	for _, platform := range []string{attestation.PlatformSEVSNP, attestation.PlatformTDX} {
		t.Run(platform, func(t *testing.T) {
			doc, err := attestation.V2Document(quote, platform)
			if err != nil {
				t.Fatal(err)
			}
			request, ok, err := attestationmaterial.Request(doc, &config.ExternalConfig{Metadata: config.Metadata{Repo: "repo", Tag: "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			if !ok || request.Repo != "repo" || request.Tag != "v1" || request.Platform != platform {
				t.Fatalf("request = %+v, ok = %t", request, ok)
			}
			got, err := base64.StdEncoding.DecodeString(request.QuoteBase64)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(quote) {
				t.Fatalf("quote = %q, want %q", got, quote)
			}
		})
	}
}
