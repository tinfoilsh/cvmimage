// Package dcode encodes byte payloads as chunked DNS labels for the legacy
// SAN-based key/attestation binding (the v3 flow does not use it).
package dcode

import (
	"encoding/base32"
	"fmt"
	"strings"
)

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
		if index > 99 {
			return nil, fmt.Errorf("payload requires %d+ chunks; 2-digit prefix supports at most 100", index+1)
		}
		domains = append(domains, fmt.Sprintf("%02d%s%s", index, chunk, domainSuffix))
	}

	return domains, nil
}
