package timeanchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

var pinnedAuthorityNames = []string{"certum", "digicert", "sectigo", "sigstore"}

func TestPinnedRootsAreDistinctAuthorityCertificates(t *testing.T) {
	authorities, err := PinnedAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, authority := range authorities {
		names = append(names, authority.Name)
	}
	if !slices.Equal(names, pinnedAuthorityNames) {
		t.Fatalf("pinned authorities = %v, want %v", names, pinnedAuthorityNames)
	}
	owners := make(map[string]string)
	for _, name := range names {
		encoded, err := rootFiles.ReadFile(path.Join(rootsDir, name+rootSuffix))
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(encoded)
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("%s must hold exactly one certificate", name)
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !root.BasicConstraintsValid || !root.IsCA {
			t.Fatalf("%s is not a certificate authority", name)
		}
		key := string(root.RawSubjectPublicKeyInfo)
		if owner, shared := owners[key]; shared {
			t.Fatalf("%s and %s share a key, so one authority would count twice", owner, name)
		}
		owners[key] = name
	}
}

func TestVerifyRejectsAlteredAndMisdirectedReplies(t *testing.T) {
	a, b := newTestAuthority(t, "a"), newTestAuthority(t, "b")
	pinned := []Authority{a.Authority, b.Authority}
	asked, err := newQuery()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseRequest(asked.encoded)
	if err != nil {
		t.Fatal(err)
	}
	reply := a.sign(t, parsed, time.Now())
	if name, _, err := asked.verify(reply, pinned); err != nil || name != a.Name {
		t.Fatalf("reply verified as %q: %v", name, err)
	}
	if _, _, err := asked.verify(reply, pinned[1:]); err == nil {
		t.Fatal("reply verified against another authority's roots")
	}
	altered := bytes.Clone(reply)
	altered[len(altered)-1] ^= 1
	if _, _, err := asked.verify(altered, pinned); err == nil {
		t.Fatal("reply verified with an altered signature")
	}
	other, err := newQuery()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.verify(reply, pinned); err == nil {
		t.Fatal("reply verified for another query")
	}
}

func TestAgreeNeedsTwoAuthoritiesNearTheMedian(t *testing.T) {
	base := time.Date(2026, time.November, 13, 19, 15, 7, 0, time.UTC)
	const tolerance = 3 * time.Second
	for name, test := range map[string]struct {
		issued map[string]time.Duration
		want   time.Duration
		names  []string
	}{
		"all agree":        {map[string]time.Duration{"a": 0, "b": time.Second, "c": 2 * time.Second}, time.Second, []string{"a", "b", "c"}},
		"one far behind":   {map[string]time.Duration{"a": -30 * 24 * time.Hour, "b": 0, "c": time.Second}, 0, []string{"b", "c"}},
		"one far ahead":    {map[string]time.Duration{"a": 0, "b": time.Second, "c": 30 * 24 * time.Hour}, time.Second, []string{"a", "b"}},
		"two answer":       {map[string]time.Duration{"a": 0, "b": 2 * time.Second}, 2 * time.Second, []string{"a", "b"}},
		"two disagree":     {map[string]time.Duration{"a": 0, "b": time.Hour}, 0, nil},
		"one answers":      {map[string]time.Duration{"a": 0}, 0, nil},
		"three all differ": {map[string]time.Duration{"a": 0, "b": time.Hour, "c": 2 * time.Hour}, 0, nil},
	} {
		t.Run(name, func(t *testing.T) {
			issued := make(map[string]time.Time)
			for authority, offset := range test.issued {
				issued[authority] = base.Add(offset)
			}
			at, names, err := agree(issued, tolerance)
			if test.names == nil {
				if err == nil {
					t.Fatalf("agreed on %s by %v", at, names)
				}
				return
			}
			if err != nil || !at.Equal(base.Add(test.want)) || !slices.Equal(names, test.names) {
				t.Fatalf("agree = %s by %v, %v", at.Sub(base), names, err)
			}
		})
	}
}

type testAuthority struct {
	Authority
	signer *x509.Certificate
	key    *ecdsa.PrivateKey
}

func newTestAuthority(t *testing.T, name string) testAuthority {
	t.Helper()
	issue := func(template, parent *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	valid := func(template *x509.Certificate) *x509.Certificate {
		template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		return template
	}
	rootKey, signerKey := newKey(), newKey()
	rootTemplate := valid(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign})
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	signer := issue(valid(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name + " signer"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}),
		root, &signerKey.PublicKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return testAuthority{Authority: Authority{Name: name, Roots: roots}, signer: signer, key: signerKey}
}

func (authority testAuthority) sign(t *testing.T, asked *timestamp.Request, at time.Time) []byte {
	t.Helper()
	reply, err := (&timestamp.Timestamp{HashAlgorithm: asked.HashAlgorithm, HashedMessage: asked.HashedMessage,
		Time: at, Nonce: asked.Nonce, Policy: asn1.ObjectIdentifier{1, 2, 3}, AddTSACertificate: true}).CreateResponse(authority.signer, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestAcquireAnchorsOnAgreeingAuthorities(t *testing.T) {
	a, b, c := newTestAuthority(t, "a"), newTestAuthority(t, "b"), newTestAuthority(t, "c")
	pinned := []Authority{a.Authority, b.Authority, c.Authority}
	stranger := newTestAuthority(t, "stranger")
	const rollback = -30 * 24 * time.Hour
	now := func(*timestamp.Request) time.Duration { return 0 }
	for name, test := range map[string]struct {
		answers map[*testAuthority]func(*timestamp.Request) time.Duration
		names   []string
	}{
		"all honest":             {map[*testAuthority]func(*timestamp.Request) time.Duration{&a: now, &b: now, &c: now}, []string{"a", "b", "c"}},
		"one rolled back":        {map[*testAuthority]func(*timestamp.Request) time.Duration{&a: func(*timestamp.Request) time.Duration { return rollback }, &b: now, &c: now}, []string{"b", "c"}},
		"one silent":             {map[*testAuthority]func(*timestamp.Request) time.Duration{&a: now, &c: now}, []string{"a", "c"}},
		"only one answers":       {map[*testAuthority]func(*timestamp.Request) time.Duration{&b: now}, nil},
		"two disagree":           {map[*testAuthority]func(*timestamp.Request) time.Duration{&a: func(*timestamp.Request) time.Duration { return rollback }, &b: now}, nil},
		"one and a stranger":     {map[*testAuthority]func(*timestamp.Request) time.Duration{&a: now, &stranger: now}, nil},
		"replayed for old nonce": {map[*testAuthority]func(*timestamp.Request) time.Duration{&a: func(asked *timestamp.Request) time.Duration { asked.Nonce = big.NewInt(1); return 0 }, &b: func(asked *timestamp.Request) time.Duration { asked.Nonce = big.NewInt(1); return 0 }}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Method != http.MethodPost || r.URL.Path != relayPath || r.Header.Get("Content-Type") != queryType {
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				var reply struct {
					Responses [][]byte `json:"responses"`
				}
				for authority, offset := range test.answers {
					asked, err := timestamp.ParseRequest(body)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					reply.Responses = append(reply.Responses, authority.sign(t, asked, time.Now().Add(offset(asked))))
				}
				json.NewEncoder(w).Encode(reply)
			}))
			defer relay.Close()
			client, err := NewClient(relay.URL, pinned)
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := client.Acquire(context.Background())
			if test.names == nil {
				if err == nil {
					t.Fatalf("anchored at %s by %v", anchor.UTC, anchor.Authorities)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(anchor.Authorities, test.names) {
				t.Fatalf("anchored by %v, want %v", anchor.Authorities, test.names)
			}
			if drift := anchor.Now().Sub(time.Now()).Abs(); drift > authorityAccuracy {
				t.Fatalf("anchor is %s from the authorities' clock", drift)
			}
		})
	}
}

func TestAcquireCountsEachAuthorityOnce(t *testing.T) {
	a, b := newTestAuthority(t, "a"), newTestAuthority(t, "b")
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		asked, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string][][]byte{"responses": {a.sign(t, asked, time.Now()), a.sign(t, asked, time.Now())}})
	}))
	defer relay.Close()
	client, err := NewClient(relay.URL, []Authority{a.Authority, b.Authority})
	if err != nil {
		t.Fatal(err)
	}
	if anchor, err := client.Acquire(context.Background()); err == nil {
		t.Fatalf("one authority answering twice anchored the clock by %v", anchor.Authorities)
	}
}

func TestClientRequiresAnHTTPSRelayAndEnoughAuthorities(t *testing.T) {
	pinned := []Authority{newTestAuthority(t, "a").Authority, newTestAuthority(t, "b").Authority}
	for _, relay := range []string{"http://relay.example", "https://", "https://user@relay.example", "https://relay.example?x=1", "relay.example"} {
		if _, err := NewClient(relay, pinned); err == nil {
			t.Fatalf("accepted relay %q", relay)
		}
	}
	if _, err := NewClient("https://relay.example", pinned[:1]); err == nil {
		t.Fatal("accepted a single authority")
	}
}
