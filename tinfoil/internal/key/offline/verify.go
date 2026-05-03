package offline

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"time"

	"tinfoil/internal/key/keyreq"
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

// ValidateWithIP delegates to Validate. The offline validator has no notion
// of caller IPs or model policy, so the key-and-IP variant performs the same
// signature and expiry checks as the key-only path.
func (v *Validator) ValidateWithIP(req keyreq.Request) error {
	return v.Validate(req)
}

// Validate checks if an API key is signed and not expired. The Model field
// of req is ignored: model policy is enforced by the control plane and has
// no equivalent in the offline path.
func (v *Validator) Validate(req keyreq.Request) error {
	data, err := base64.RawURLEncoding.DecodeString(req.APIKey)
	if err != nil {
		return ErrInvalidKeyFormat
	}
	if len(data) != totalSize {
		return ErrInvalidKeyLength
	}

	message := data[:messageSize]
	signature := data[messageSize:]

	if len(v.publicKey) != ed25519.PublicKeySize || !ed25519.Verify(v.publicKey, message, signature) {
		return ErrInvalidSignature
	}

	timestamp := int64(binary.BigEndian.Uint64(data[nonceSize : nonceSize+timestampSize]))
	validity := int64(binary.BigEndian.Uint64(data[nonceSize+timestampSize : nonceSize+timestampSize+validitySize]))

	if time.Since(time.Unix(timestamp, 0)) > time.Duration(validity)*time.Second {
		return ErrAPIKeyExpired
	}

	return nil
}
