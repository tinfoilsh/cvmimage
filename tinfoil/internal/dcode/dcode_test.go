package dcode

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

func TestDcode(t *testing.T) {
	attJSON := `{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v1","body":"AgAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAHAAAAAAAOSAEAAAAAAAAAAAAAAAAAAAA0NWUzYzMzMGUwNmJmOWMxZjhhMTk3MjY2YWNhNWIyZjYwNjdjYTY3MTliNjFiZTY2ZDA0M2I5M2RiOTkwYTg1pbDO1EKABUY06EUsfj2O0Mck9pCpNNU09zjmp0q75OMmy7Ri71JFfU/fjzZf6hhEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACfpCeQfLGlscId5BeSdU7L9KPEStDMwQBd808awA+Lv//////////////////////////////////////////BwAAAAAADkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADyerBPBb0BVIg1GpCjfyjOa7GVEfbmBlI2UlOv2mBy2PUlhAoxzCPRyGlUox+FWyw/5T1fgVISjEAzuoWzsKeXBwAAAAAADkgVNwEAFTcBAAcAAAAAAA5IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1Mswgg2AZ5e1wct6QcyLfOAKrb6jCKQRNateCyHdAdEKBTusDgtrXpEFXR/39cQVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc9yN4XkSVWve3jGL93egyyv2O6hLAdV5JVm/j1qugeFIfr+DKUBYB5WcU+jSeKy5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
	var att attestation.Document
	if err := json.Unmarshal([]byte(attJSON), &att); err != nil {
		panic(err)
	}

	domains, err := EncodeAtt(&att, "example.com")
	if err != nil {
		t.Fatalf("EncodeAtt failed: %v", err)
	}

	for _, domain := range domains {
		assert.True(t, strings.HasSuffix(domain, ".example.com"))
	}

	t.Logf("encoded %d bytes into %d domains", len(attJSON), len(domains))

	// Randomize domain order
	rand.Shuffle(len(domains), func(i, j int) {
		domains[i], domains[j] = domains[j], domains[i]
	})

	for _, domain := range domains {
		t.Logf("domain: %s", domain)
	}

	decoded, err := Decode(domains)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	assert.Equal(t, att, *decoded)
}

func TestEncodeRejectsTooManyChunks(t *testing.T) {
	// Force >100 chunks: each chunk is one base32 char + index prefix + suffix.
	domain := "x.example.com"
	maxLength := 63 - len(".x.example.com") - 2
	if maxLength <= 0 {
		t.Fatal("test domain too long")
	}
	content := make([]byte, maxLength*101)
	_, err := Encode(content, domain)
	if err == nil {
		t.Fatal("expected error when chunk count exceeds 100")
	}
}

func TestEncodeRejectsEmptyPayload(t *testing.T) {
	if _, err := Encode(nil, "example.com"); err == nil {
		t.Fatal("Encode accepted an empty payload")
	}
}

func TestDecodeRejectsMalformedChunkSets(t *testing.T) {
	for name, domains := range map[string][]string{
		"empty":     nil,
		"too many":  make([]string, maxDomainChunks+1),
		"duplicate": {"00aa.example.com", "00bb.example.com"},
		"gap":       {"00aa.example.com", "02bb.example.com"},
		"bad index": {"xxaa.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(domains); err == nil {
				t.Fatalf("Decode accepted %s", name)
			}
		})
	}
}

func TestDecodeRejectsDecompressionBomb(t *testing.T) {
	exact := gzipBytes(t, make([]byte, maxDecompressedAttBytes))
	if decompressed, err := gzDecompress(exact); err != nil || len(decompressed) != maxDecompressedAttBytes {
		t.Fatalf("exact decompression limit: len=%d error=%v", len(decompressed), err)
	}

	compressed := gzipBytes(t, make([]byte, maxDecompressedAttBytes+1))
	if _, err := gzDecompress(compressed); err == nil || !strings.Contains(err.Error(), "decompressed payload exceeds") {
		t.Fatalf("decompression bomb error = %v", err)
	}
}

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}
