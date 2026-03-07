package tls

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
)

func KeyFPBytes(publicKey *ecdsa.PublicKey) [32]byte {
	bytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	return sha256.Sum256(bytes)
}
