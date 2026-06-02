// Package jwt verifies OAuth 2.0 JWT access tokens (RFC 9068) locally inside
// the enclave. It fetches the control plane's JWKS once at boot, refreshes it
// periodically to follow signing-key rotation, and validates token signatures
// and claims without a per-request call to the control plane.
package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"tinfoil/internal/key"
)

const (
	// AccessTokenAudience must match the control plane's OAuthAccessTokenAudience
	// (the aud claim stamped on inference access tokens).
	AccessTokenAudience = "https://inference.tinfoil.sh"

	// RequiredScope is the OAuth scope a token must carry to call chat inference.
	RequiredScope = "inference:chat"

	// accessTokenType is the RFC 9068 "typ" header that distinguishes an OAuth
	// access token from other JWTs signed by the same key.
	accessTokenType = "at+jwt"

	// refreshInterval is how often the cached JWKS is refreshed to follow
	// signing-key rotation.
	refreshInterval = 15 * time.Minute

	// minRefreshInterval throttles on-demand refreshes triggered by an unknown
	// key id so malformed tokens cannot force unbounded JWKS fetches.
	minRefreshInterval = time.Minute

	// fetchTimeout bounds a single JWKS fetch.
	fetchTimeout = 10 * time.Second
)

// signingKeys caches a JWKS and refreshes it from the issuer.
type signingKeys struct {
	url    string
	client *http.Client

	mu          sync.RWMutex
	set         jose.JSONWebKeySet
	lastRefresh time.Time
	lastAttempt time.Time
}

func newSigningKeys(jwksURL string) (*signingKeys, error) {
	s := &signingKeys{url: jwksURL, client: &http.Client{Timeout: fetchTimeout}}
	if err := s.refresh(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *signingKeys) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return fmt.Errorf("building jwks request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching jwks: unexpected status %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decoding jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("jwks contains no keys")
	}
	s.mu.Lock()
	s.set = set
	s.lastRefresh = time.Now()
	s.mu.Unlock()
	return nil
}

// lookup returns the verification key for kid, if present.
func (s *signingKeys) lookup(kid string) (jose.JSONWebKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	matches := s.set.Key(kid)
	if len(matches) == 0 {
		return jose.JSONWebKey{}, false
	}
	return matches[0], true
}

// refreshIfStale triggers an on-demand JWKS refresh when a token carries an
// unknown key id, so a rotated key can be picked up without a restart. It is
// throttled on the last attempt time rather than the last success, so that a
// JWKS outage combined with unknown-kid traffic cannot fan out into unbounded
// fetch attempts.
func (s *signingKeys) refreshIfStale() {
	s.mu.Lock()
	if time.Since(s.lastRefresh) < minRefreshInterval || time.Since(s.lastAttempt) < minRefreshInterval {
		s.mu.Unlock()
		return
	}
	s.lastAttempt = time.Now()
	s.mu.Unlock()

	if err := s.refresh(context.Background()); err != nil {
		log.Printf("Warning: on-demand JWKS refresh failed: %v", err)
	}
}

func (s *signingKeys) startBackgroundRefresh() {
	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := s.refresh(context.Background()); err != nil {
				log.Printf("Warning: periodic JWKS refresh failed: %v", err)
			}
		}
	}()
}

// Validator verifies RFC 9068 JWT access tokens against a cached JWKS. Opaque
// (non-JWT) credentials yield key.ErrUnsupportedToken so a Chain falls back to
// the control-plane validator.
type Validator struct {
	keys     *signingKeys
	issuer   string
	audience string
	scope    string
}

// NewValidator fetches the issuer's JWKS, starts periodic refresh, and returns
// a Validator. It returns an error if the initial JWKS fetch fails so the
// caller can fall back to online-only validation.
func NewValidator(jwksURL, issuer, audience, requiredScope string) (*Validator, error) {
	keys, err := newSigningKeys(jwksURL)
	if err != nil {
		return nil, err
	}
	keys.startBackgroundRefresh()
	return &Validator{
		keys:     keys,
		issuer:   strings.TrimRight(issuer, "/"),
		audience: audience,
		scope:    requiredScope,
	}, nil
}

func (v *Validator) Validate(req key.Request) error {
	if !looksLikeJWT(req.APIKey) {
		return key.ErrUnsupportedToken
	}

	token, err := josejwt.ParseSigned(req.APIKey, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(token.Headers) == 0 {
		return &key.ValidationError{StatusCode: http.StatusUnauthorized}
	}

	// RFC 9068 registers the access-token type as "at+jwt"; RFC 7515 also
	// permits the equivalent media type carrying an "application/" prefix, so
	// accept both forms case-insensitively.
	typ, _ := token.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	typ = strings.TrimPrefix(strings.ToLower(typ), "application/")
	if typ != accessTokenType {
		return &key.ValidationError{StatusCode: http.StatusUnauthorized}
	}

	signingKey, ok := v.keys.lookup(token.Headers[0].KeyID)
	if !ok {
		v.keys.refreshIfStale()
		signingKey, ok = v.keys.lookup(token.Headers[0].KeyID)
		if !ok {
			return &key.ValidationError{StatusCode: http.StatusUnauthorized}
		}
	}

	var claims josejwt.Claims
	var ext struct {
		Scope string `json:"scope"`
	}
	if err := token.Claims(signingKey, &claims, &ext); err != nil {
		return &key.ValidationError{StatusCode: http.StatusUnauthorized}
	}

	if err := claims.Validate(josejwt.Expected{
		Issuer:      v.issuer,
		AnyAudience: josejwt.Audience{v.audience},
		Time:        time.Now(),
	}); err != nil {
		return &key.ValidationError{StatusCode: http.StatusUnauthorized}
	}

	if !scopeContains(ext.Scope, v.scope) {
		return &key.ValidationError{StatusCode: http.StatusForbidden}
	}

	return nil
}

// looksLikeJWT reports whether s has the three-segment compact JWS shape, so
// opaque API keys (which contain no dots) are routed to the online validator.
func looksLikeJWT(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// scopeContains reports whether the space-delimited scope string includes want.
func scopeContains(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}
