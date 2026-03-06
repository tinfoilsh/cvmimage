package offline

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	validity   time.Duration
}

func NewSigner(validity time.Duration) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: priv,
		publicKey:  pub,
		validity:   validity,
	}, nil
}

// PubKey returns the public key in base64 format
func (s *Signer) PubKey() string {
	return base64.RawURLEncoding.EncodeToString(s.publicKey)
}

// NewAPIKey generates a new random API key
func (s *Signer) NewAPIKey() (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))

	validityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(validityBytes, uint64(s.validity.Seconds()))

	message := make([]byte, 0, nonceSize+timestampSize+validitySize)
	message = append(message, nonce...)
	message = append(message, timeBytes...)
	message = append(message, validityBytes...)

	signature := ed25519.Sign(s.privateKey, message)

	finalKey := make([]byte, 0, totalSize)
	finalKey = append(finalKey, message...)
	finalKey = append(finalKey, signature...)

	return base64.RawURLEncoding.EncodeToString(finalKey), nil
}
