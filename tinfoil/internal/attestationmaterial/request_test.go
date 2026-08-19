package attestationmaterial

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"testing"

	"tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

func TestRequestRejectsOversizedQuote(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(make([]byte, maxCPUQuoteBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	document := &legacy.Document{
		Format: legacy.SevGuestV2,
		Body:   base64.StdEncoding.EncodeToString(compressed.Bytes()),
	}
	_, _, err := Request(document, &config.ExternalConfig{Metadata: config.Metadata{Repo: "repo"}})
	if err == nil {
		t.Fatal("oversized quote accepted")
	}
}
