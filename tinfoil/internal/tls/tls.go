package tls

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

func KeyFPBytes(publicKey *ecdsa.PublicKey) [32]byte {
	bytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	return sha256.Sum256(bytes)
}

// KeyFP returns the fingerprint of a given ECDSA public key
func KeyFP(publicKey *ecdsa.PublicKey) string {
	fp := KeyFPBytes(publicKey)
	return hex.EncodeToString(fp[:])
}
