package offline

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"time"
)

type Validator struct {
	publicKey ed25519.PublicKey
}

func NewValidator(publicKey string) (*Validator, error) {
	pk, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	return &Validator{
		publicKey: pk,
	}, nil
}

// Validate checks if an API key is signed and not expired
func (v *Validator) Validate(apiKey string) error {
	data, err := base64.RawURLEncoding.DecodeString(apiKey)
	if err != nil {
		return ErrInvalidKeyFormat
	}
	if len(data) != totalSize {
		return ErrInvalidKeyLength
	}

	message := data[:nonceSize+timestampSize+validitySize]
	signature := data[nonceSize+timestampSize+validitySize:]

	timestamp := int64(binary.BigEndian.Uint64(data[nonceSize : nonceSize+timestampSize]))
	validity := int64(binary.BigEndian.Uint64(data[nonceSize+timestampSize : nonceSize+timestampSize+validitySize]))

	if time.Since(time.Unix(timestamp, 0)) > time.Duration(validity)*time.Second {
		return ErrAPIKeyExpired
	}

	if !ed25519.Verify(v.publicKey, message, signature) {
		return ErrInvalidSignature
	}

	return nil
}
