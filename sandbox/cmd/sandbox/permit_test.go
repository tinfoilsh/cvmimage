package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func testSandbox(t *testing.T) (*sandbox, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &sandbox{domain: "sandbox.example", nonce: "test-boot", permit: &key.PublicKey}, key
}

func testClaims() map[string]any {
	return map[string]any{
		"iss": permitIssuer, "sub": "sandbox.example", "aud": "test-boot",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func signPermit(t *testing.T, key *ecdsa.PrivateKey, algorithm string, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	input := encode(map[string]string{"alg": algorithm}) + "." + encode(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestPermitBindsIssuerSandboxAndBoot(t *testing.T) {
	box, key := testSandbox(t)
	for _, audience := range []any{"test-boot", []string{"another-boot", "test-boot"}} {
		claims := testClaims()
		claims["aud"] = audience
		if err := box.check(signPermit(t, key, "ES256", claims)); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name, field string
		value       any
	}{
		{"issuer", "iss", "https://other.example"},
		{"sandbox", "sub", "other.example"},
		{"boot", "aud", "another-boot"},
		{"audience type", "aud", 42},
		{"expired", "exp", time.Now().Add(-time.Hour).Unix()},
		{"missing expiry", "exp", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := testClaims()
			claims[test.field] = test.value
			if err := box.check(signPermit(t, key, "ES256", claims)); err == nil {
				t.Fatal("accepted a permit that does not authorize this boot")
			}
		})
	}
}

func TestPermitRequiresExpectedKeyAndAlgorithm(t *testing.T) {
	box, key := testSandbox(t)
	_, other := testSandbox(t)
	for _, token := range []string{
		signPermit(t, other, "ES256", testClaims()),
		signPermit(t, key, "other", testClaims()),
		"", "invalid", "a.b.c",
	} {
		if err := box.check(token); err == nil {
			t.Fatal("accepted an invalid signature or header")
		}
	}
}
