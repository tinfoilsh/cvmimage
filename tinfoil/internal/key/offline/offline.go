package offline

import (
	"crypto/ed25519"
	"errors"
)

const (
	nonceSize     = 16
	timestampSize = 8
	validitySize  = 8
	messageSize   = nonceSize + timestampSize + validitySize
	totalSize     = messageSize + ed25519.SignatureSize
)

var (
	ErrInvalidKeyFormat = errors.New("invalid key format")
	ErrInvalidKeyLength = errors.New("invalid key length")
	ErrAPIKeyExpired    = errors.New("API key has expired")
	ErrInvalidSignature = errors.New("invalid key signature")
)
