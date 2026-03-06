package offline

import (
	"crypto/ed25519"
	"fmt"
)

const (
	nonceSize     = 16
	timestampSize = 8
	validitySize  = 8
	totalSize     = nonceSize + timestampSize + validitySize + ed25519.SignatureSize
)

var (
	ErrInvalidKeyFormat = fmt.Errorf("invalid key format")
	ErrInvalidKeyLength = fmt.Errorf("invalid key length")
	ErrAPIKeyExpired    = fmt.Errorf("API key has expired")
	ErrInvalidSignature = fmt.Errorf("invalid key signature")
)
