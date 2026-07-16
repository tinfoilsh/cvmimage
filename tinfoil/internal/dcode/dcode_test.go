package dcode

import (
	"encoding/base32"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeDomains reverses Encode: sort chunks by their NN prefix, strip the
// prefix and suffix, and base32-decode. Verification-side decoding lives in
// tinfoil-go's certificate checks; this test-local copy keeps the round-trip
// property covered here.
func decodeDomains(t *testing.T, domains []string) []byte {
	t.Helper()
	sorted := append([]string(nil), domains...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i][:2] < sorted[j][:2]
	})
	var encoded string
	for _, domain := range sorted {
		label := strings.Split(domain, ".")[0]
		require.GreaterOrEqual(t, len(label), 3, "malformed domain chunk %q", domain)
		encoded += label[2:]
	}
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	content, err := decoder.DecodeString(strings.ToUpper(encoded))
	require.NoError(t, err)
	return content
}

func TestEncodeRoundTrip(t *testing.T) {
	content := make([]byte, 1500)
	for i := range content {
		content[i] = byte(i * 7)
	}

	domains, err := Encode(content, "example.com")
	require.NoError(t, err)
	for _, domain := range domains {
		assert.True(t, strings.HasSuffix(domain, ".example.com"))
		assert.LessOrEqual(t, len(strings.Split(domain, ".")[0]), 63)
	}
	t.Logf("encoded %d bytes into %d domains", len(content), len(domains))

	// Order must not matter: chunks carry their own index.
	rand.Shuffle(len(domains), func(i, j int) {
		domains[i], domains[j] = domains[j], domains[i]
	})

	assert.Equal(t, content, decodeDomains(t, domains))
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
