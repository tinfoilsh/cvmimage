package boot

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// Input validation patterns
var (
	hexHashPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`) // SHA256 hex strings
	secretNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// sha256Hash computes the SHA256 hash of data and returns hex string
func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
