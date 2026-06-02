package jwt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
		Claims(map[string]interface{}{"scope": scope, "client_id": "tinfoil-chat"}).
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
	return NewValidator(jwksURL, testIssuer, AccessTokenAudience, RequiredScope)
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

func chatRequest(token string) key.Request {
	return key.Request{APIKey: token, Path: chatCompletionsPath}
}

func TestValidateAcceptsValidToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now()), RequiredScope)
	if err := v.Validate(chatRequest(token)); err != nil {
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

func TestValidateFallsThroughForDottedOpaqueKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	err := v.Validate(key.Request{APIKey: "opaque.with.dots"})
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
	expectStatus(t, v.Validate(chatRequest(token)), http.StatusUnauthorized)
}

func TestValidateRejectsExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now().Add(-time.Hour)), RequiredScope)
	expectStatus(t, v.Validate(chatRequest(token)), http.StatusUnauthorized)
}

func TestValidateRejectsMissingExpiration(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	claims := validClaims(time.Now())
	claims.Expiry = nil
	token := mintToken(t, priv, testKID, "at+jwt", claims, RequiredScope)
	expectStatus(t, v.Validate(chatRequest(token)), http.StatusUnauthorized)
}

func TestValidateRejectsMissingScope(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now()), "models:read")
	expectStatus(t, v.Validate(chatRequest(token)), http.StatusForbidden)
}

func TestValidateRejectsWrongIssuer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	claims := validClaims(time.Now())
	claims.Issuer = "https://evil.example.com"
	token := mintToken(t, priv, testKID, "at+jwt", claims, RequiredScope)
	expectStatus(t, v.Validate(chatRequest(token)), http.StatusUnauthorized)
}

func TestValidateFallsThroughForWrongType(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "JWT", validClaims(time.Now()), RequiredScope)
	err := v.Validate(chatRequest(token))
	if !errors.Is(err, key.ErrUnsupportedToken) {
		t.Fatalf("expected ErrUnsupportedToken, got %v", err)
	}
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
	expectStatus(t, v.Validate(chatRequest(token)), http.StatusUnauthorized)
}

func TestValidateAcceptsApplicationPrefixType(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	// RFC 9068 / RFC 7515 permit the media type with an "application/" prefix.
	token := mintToken(t, priv, testKID, "application/at+jwt", validClaims(time.Now()), RequiredScope)
	if err := v.Validate(chatRequest(token)); err != nil {
		t.Fatalf("expected application/at+jwt to be accepted, got %v", err)
	}
}

func TestValidateRejectsChatTokenOnNonChatPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, pub, testKID)
	defer srv.Close()
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now()), RequiredScope)
	expectStatus(t, v.Validate(key.Request{APIKey: token, Path: "/v1/embeddings"}), http.StatusForbidden)
}

func TestRefreshIfAllowedThrottlesFailedAttempts(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       pub,
		KeyID:     testKID,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	var fetches int32
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	s := newSigningKeys(srv.URL) // successful boot fetch (#1)
	failing.Store(true)

	// Make on-demand refresh eligible to run.
	s.mu.Lock()
	s.lastAttempt = time.Now().Add(-2 * minRefreshInterval)
	s.mu.Unlock()

	// A burst of unknown-kid lookups during an outage must trigger at most one
	// on-demand fetch within the throttle window, not one per call.
	for i := 0; i < 5; i++ {
		s.refreshIfAllowed()
	}

	if got := atomic.LoadInt32(&fetches); got != 2 {
		t.Fatalf("expected 1 boot + 1 throttled on-demand fetch, got %d", got)
	}
}

func TestValidateRefreshesUnknownKidAfterRecentSuccess(t *testing.T) {
	firstPub, _, _ := ed25519.GenerateKey(nil)
	secondPub, secondPriv, _ := ed25519.GenerateKey(nil)

	var useSecond atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pub := firstPub
		kid := testKID
		if useSecond.Load() {
			pub = secondPub
			kid = "test-key-2"
		}
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       pub,
			KeyID:     kid,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}}}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	v := newTestValidator(t, srv.URL)
	useSecond.Store(true)

	token := mintToken(t, secondPriv, "test-key-2", "at+jwt", validClaims(time.Now()), RequiredScope)
	if err := v.Validate(chatRequest(token)); err != nil {
		t.Fatalf("expected unknown kid to refresh immediately, got %v", err)
	}
}

func TestNewValidatorRecoversWhenJWKSStartsUnavailable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       pub,
		KeyID:     testKID,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	var serving atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !serving.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Boot while the JWKS endpoint is unavailable: the validator must come up
	// with an empty key set instead of failing.
	v := newTestValidator(t, srv.URL)

	token := mintToken(t, priv, testKID, "at+jwt", validClaims(time.Now()), RequiredScope)
	if err := v.Validate(chatRequest(token)); err == nil {
		t.Fatal("expected rejection while no signing keys are cached")
	}

	// Once the JWKS is reachable, the unknown-kid path triggers an on-demand
	// refresh and the same token validates without a restart.
	serving.Store(true)
	v.keys.mu.Lock()
	v.keys.lastAttempt = time.Now().Add(-2 * minRefreshInterval)
	v.keys.mu.Unlock()

	if err := v.Validate(chatRequest(token)); err != nil {
		t.Fatalf("expected token to validate after JWKS became available, got %v", err)
	}
}
