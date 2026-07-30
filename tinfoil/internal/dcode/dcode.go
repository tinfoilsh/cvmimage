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

const (
	maxDomainChunks         = 100
	maxDecompressedAttBytes = 1 << 20
)

func gzDecompress(data []byte) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()
	decompressed, err := io.ReadAll(io.LimitReader(gzReader, maxDecompressedAttBytes+1))
	if err != nil {
		return nil, err
	}
	if len(decompressed) > maxDecompressedAttBytes {
		return nil, fmt.Errorf("decompressed payload exceeds %d-byte limit", maxDecompressedAttBytes)
	}
	return decompressed, nil
}

// Encode encodes a byte slice into a string of domains
func Encode(content []byte, domain string) ([]string, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("payload must not be empty")
	}
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
		if index >= maxDomainChunks {
			return nil, fmt.Errorf("payload requires more than %d chunks", maxDomainChunks)
		}
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
	if len(domains) == 0 || len(domains) > maxDomainChunks {
		return nil, fmt.Errorf("domain chunk count must be between 1 and %d", maxDomainChunks)
	}
	for _, d := range domains {
		label := strings.SplitN(d, ".", 2)[0]
		if len(label) < 3 || len(label) > 63 {
			return nil, fmt.Errorf("malformed domain chunk: %q", d)
		}
	}

	// Sort domains by their NN prefix
	sort.Slice(domains, func(i, j int) bool {
		return domains[i][:2] < domains[j][:2]
	})
	for index, domain := range domains {
		if domain[:2] != fmt.Sprintf("%02d", index) {
			return nil, fmt.Errorf("domain chunks must have unique contiguous indexes starting at 00")
		}
	}

	// Extract encoded data from the domains
	var encodedData string
	for _, domain := range domains {
		domain = strings.SplitN(domain, ".", 2)[0]
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
