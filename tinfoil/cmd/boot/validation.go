package main

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// Input validation patterns
var (
	hexHashPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`) // SHA256 hex strings
	uuidPattern     = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	offsetPattern   = regexp.MustCompile(`^[0-9]+$`)                              // Numeric offset
	versionPattern  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)             // Version tags (v1.2.3)
	registryPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`) // Registry hostnames
)

// sha256Hash computes the SHA256 hash of data and returns hex string
func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
