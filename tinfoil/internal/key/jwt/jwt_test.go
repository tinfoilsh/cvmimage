package jwt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"tinfoil/internal/key"
)

const (
	testIssuer = "https://api.tinfoil.sh"
	testKID    = "test-key-1"
)

func mintToken(t *testing.T, priv ed25519.PrivateKey, kid, typ string, claims josejwt.Claims, scope string) string {
	t.Helper()
	signingKey := jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.EdDSA)}
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: signingKey}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	token, err := josejwt.Signed(signer).
		Claims(claims).
		Claims(map[string]interface{}{"scope": scope}).
		Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return token
}

func jwksServer(t *testing.T, pub ed25519.PublicKey, kid string) *httptest.Server {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       pub,
		KeyID:     kid,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func validClaims(now time.Time) josejwt.Claims {
	return josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  "user_1",
		Audience: josejwt.Audience{AccessTokenAudience},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
		ID:       "jti-1",
	}
}

func newTestValidator(t *testing.T, jwksURL string) *Validator {
	t.Helper()
	v, err := NewValidator(jwksURL, testIssuer, AccessTokenAudience, RequiredScope)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	return v
}

func expectStatus(t *testing.T, err error, want int) {
	t.Helper()
	var ve *key.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	if ve.StatusCode != want {
		t.Fatalf("status = %d, want %d", ve.StatusCode, want)
	}
}

func TestValidateAcceptsValidToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now()), RequiredScope)
	if err := v.Validate(key.Request{APIKey: token}); err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
}

func TestValidateFallsThroughForOpaqueKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	err := v.Validate(key.Request{APIKey: "chat_abcdef"})
	if !errors.Is(err, key.ErrUnsupportedToken) {
		t.Fatalf("expected ErrUnsupportedToken, got %v", err)
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	claims := validClaims(time.Now())
	claims.Audience = josejwt.Audience{"https://example.com"}
	token := mintToken(t, priv, testKID, "at+jwt", claims, RequiredScope)
	expectStatus(t, v.Validate(key.Request{APIKey: token}), http.StatusUnauthorized)
}

func TestValidateRejectsExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now().Add(-time.Hour)), RequiredScope)
	expectStatus(t, v.Validate(key.Request{APIKey: token}), http.StatusUnauthorized)
}

func TestValidateRejectsMissingScope(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now()), "models:read")
	expectStatus(t, v.Validate(key.Request{APIKey: token}), http.StatusForbidden)
}

func TestValidateRejectsWrongIssuer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	claims := validClaims(time.Now())
	claims.Issuer = "https://evil.example.com"
	token := mintToken(t, priv, testKID, "at+jwt", claims, RequiredScope)
	expectStatus(t, v.Validate(key.Request{APIKey: token}), http.StatusUnauthorized)
}

func TestValidateRejectsWrongType(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "JWT", validClaims(time.Now()), RequiredScope)
	expectStatus(t, v.Validate(key.Request{APIKey: token}), http.StatusUnauthorized)
}

func TestValidateRejectsForeignSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	// Signed by a different key but advertising the served kid: signature
	// verification against the published key must fail.
	_, foreignPriv, _ := ed25519.GenerateKey(nil)
	token := mintToken(t, foreignPriv, testKID, "at+jwt", validClaims(time.Now()), RequiredScope)
	expectStatus(t, v.Validate(key.Request{APIKey: token}), http.StatusUnauthorized)
}
