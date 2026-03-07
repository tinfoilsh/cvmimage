package dcode

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	"tinfoil/internal/compress"
)

func gzDecompress(data []byte) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	return io.ReadAll(gzReader)
}

// Encode encodes a byte slice into a string of domains
func Encode(content []byte, domain string) ([]string, error) {
	// Encode the entire compressed data using base32
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	encoded := encoder.EncodeToString(content)
	encoded = strings.ToLower(encoded) // Make it lowercase for better readability in domains

	// Chunk
	domainSuffix := "." + domain
	maxLength := 63 - len(domainSuffix) - 2 // Reserve space for NN prefix
	if maxLength <= 0 {
		return nil, fmt.Errorf("domain %q is too long for DNS label encoding", domain)
	}
	var domains []string
	for i := 0; i < len(encoded); i += maxLength {
		end := min(i+maxLength, len(encoded))
		chunk := encoded[i:end]
		index := len(domains)
		domains = append(domains, fmt.Sprintf("%02d%s%s", index, chunk, domainSuffix))
	}

	return domains, nil
}

// EncodeAtt encodes an attestation document into a string of domains
func EncodeAtt(att *attestation.Document, domain string) ([]string, error) {
	attJSON, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation: %v", err)
	}
	compressed, err := compress.Gzip(attJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to compress attestation: %v", err)
	}
	return Encode(compressed, domain)
}

// Decode decodes a string of domains into an attestation document
func Decode(domains []string) (*attestation.Document, error) {
	for _, d := range domains {
		label := strings.Split(d, ".")[0]
		if len(label) < 3 {
			return nil, fmt.Errorf("malformed domain chunk: %q", d)
		}
	}

	// Sort domains by their NN prefix
	sort.Slice(domains, func(i, j int) bool {
		return domains[i][:2] < domains[j][:2]
	})

	// Extract encoded data from the domains
	var encodedData string
	for _, domain := range domains {
		domain = strings.Split(domain, ".")[0]
		encodedData += domain[2:]
	}

	// Decode base32
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	gzJSON, err := encoder.DecodeString(strings.ToUpper(encodedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32: %v", err)
	}

	// Decompress
	attJSON, err := gzDecompress(gzJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress attestation: %v", err)
	}

	// Unmarshal
	var att attestation.Document
	if err := json.Unmarshal(attJSON, &att); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %v", err)
	}
	return &att, nil
}
