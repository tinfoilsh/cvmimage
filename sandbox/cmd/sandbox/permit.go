package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

const (
	// The issuer and public key are measured with the image.
	permitIssuer = "https://orchestrator.tinfoil.sh"
	permitKey    = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe7Dz4UoNi9fKoAq9DMgv+moqp+dyZyVSeRlAiVlFqZNAMLaamYJotUmKSR7OAT7AND1fC47oDfzOOX9nOs72ew=="
	coordinate   = 32
)

// check verifies the signature before checking the issuer, domain, expiry, and boot nonce.
func (s *sandbox) check(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token is not a JWS")
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if err := decode(parts[0], &header); err != nil {
		return fmt.Errorf("token header: %w", err)
	}
	if header.Algorithm != "ES256" {
		return fmt.Errorf("token algorithm is %q, not ES256", header.Algorithm)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("token signature: %w", err)
	}
	if len(signature) != 2*coordinate {
		return fmt.Errorf("token signature is %d bytes, want %d", len(signature), 2*coordinate)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(s.permit,
		digest[:],
		new(big.Int).SetBytes(signature[:coordinate]),
		new(big.Int).SetBytes(signature[coordinate:]),
	) {
		return errors.New("signature does not match the key this check trusts")
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Expires  int64           `json:"exp"`
	}
	if err := decode(parts[1], &claims); err != nil {
		return fmt.Errorf("token claims: %w", err)
	}
	switch {
	case claims.Issuer != permitIssuer:
		return fmt.Errorf("token issuer is %q, not %q", claims.Issuer, permitIssuer)
	case claims.Subject != s.domain:
		return fmt.Errorf("token names %q, not this sandbox", claims.Subject)
	case claims.Expires == 0:
		return errors.New("token does not expire")
	case time.Now().After(time.Unix(claims.Expires, 0)):
		return errors.New("token has expired")
	case !slices.Contains(audiences(claims.Audience), s.nonce):
		return errors.New("token is bound to another boot")
	}
	return nil
}

func publicKey(encoded string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("key is not P-256")
	}
	return key, nil
}

func audiences(raw json.RawMessage) []string {
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	return nil
}

func decode(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}
