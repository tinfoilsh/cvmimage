package main

import (
	"crypto/ecdsa"
	"tinfoil/internal/identity/permit"
)

const (
	permitIssuer = permit.Issuer
	permitKey    = permit.PublicKey
	coordinate   = 32
)

func (s *sandbox) check(token string) error {
	return permit.CheckWithKey(s.permit, token, s.domain, s.nonce, "")
}
func publicKey(encoded string) (*ecdsa.PublicKey, error) { return permit.ParseKey(encoded) }
