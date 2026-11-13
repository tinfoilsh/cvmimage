// Package timeanchor establishes UTC from independent RFC 3161 timestamp
// authorities reached through an untrusted relay.
package timeanchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

const (
	RequiredAuthorities = 2
	ExchangeLimit       = 8 * time.Second
	authorityAccuracy   = time.Second
	nonceBytes          = 16
	nonceLeadingBit     = 0x80
	maxReplyBytes       = 128 << 10
	maxResponses        = 8
	relayPath           = "/time-anchor"
	queryType           = "application/timestamp-query"
	rootsDir            = "roots"
	rootSuffix          = ".crt"
)

//go:embed roots/*.crt
var rootFiles embed.FS

// Authority is one independently operated timestamp authority and the roots
// that authenticate it.
type Authority struct {
	Name  string
	Roots *x509.CertPool
}

// PinnedAuthorities returns the authorities compiled into the measured image.
func PinnedAuthorities() ([]Authority, error) {
	entries, err := rootFiles.ReadDir(rootsDir)
	if err != nil {
		return nil, err
	}
	var authorities []Authority
	for _, entry := range entries {
		encoded, err := rootFiles.ReadFile(path.Join(rootsDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(encoded) {
			return nil, fmt.Errorf("no timestamp root in %s", entry.Name())
		}
		authorities = append(authorities, Authority{Name: strings.TrimSuffix(entry.Name(), rootSuffix), Roots: roots})
	}
	return authorities, nil
}

// Anchor is an authenticated UTC estimate for the local instant Observed,
// which retains its monotonic reading.
type Anchor struct {
	UTC         time.Time
	Observed    time.Time
	Authorities []string
}

// Now extends the estimate by the local time elapsed since it was observed.
func (anchor Anchor) Now() time.Time { return anchor.UTC.Add(time.Since(anchor.Observed)) }

type Client struct {
	relay       string
	http        *http.Client
	authorities []Authority
}

func NewClient(relay string, authorities []Authority) (*Client, error) {
	parsed, err := url.Parse(relay)
	if err != nil {
		return nil, fmt.Errorf("invalid time relay: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("time relay must be an HTTPS base URL")
	}
	if len(authorities) < RequiredAuthorities {
		return nil, fmt.Errorf("fewer than %d timestamp authorities are pinned", RequiredAuthorities)
	}
	return &Client{relay: strings.TrimRight(relay, "/") + relayPath, authorities: authorities, http: &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			// The initial date is untrusted, so the relay's certificate dates
			// cannot be judged. Every timestamp is authenticated against the
			// pinned authorities; the relay can only deny service.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Acquire asks every authority to sign one fresh nonce and returns their
// agreed time. The exchange duration bounds how stale that time can be.
func (client *Client) Acquire(parent context.Context) (Anchor, error) {
	ctx, cancel := context.WithTimeout(parent, ExchangeLimit)
	defer cancel()
	query, err := newQuery()
	if err != nil {
		return Anchor{}, err
	}
	sent := time.Now()
	replies, err := client.exchange(ctx, query.encoded)
	if err != nil {
		return Anchor{}, err
	}
	received := time.Now()
	elapsed := received.Sub(sent)
	issued := make(map[string]time.Time)
	var failures []error
	for _, reply := range replies {
		name, at, err := query.verify(reply, client.authorities)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if _, seen := issued[name]; !seen {
			issued[name] = at
		}
	}
	// Honest authorities sign within the exchange and within their own accuracy.
	at, names, err := agree(issued, elapsed+2*authorityAccuracy)
	if err != nil {
		return Anchor{}, errors.Join(append([]error{err}, failures...)...)
	}
	return Anchor{UTC: at.Add(elapsed / 2), Observed: received, Authorities: names}, nil
}

func (client *Client) exchange(ctx context.Context, query []byte) ([][]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.relay, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", queryType)
	response, err := client.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("time relay returned HTTP %d", response.StatusCode)
	}
	var reply struct {
		Responses [][]byte `json:"responses"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxReplyBytes)).Decode(&reply); err != nil {
		return nil, fmt.Errorf("time relay reply: %w", err)
	}
	if len(reply.Responses) > maxResponses {
		return nil, errors.New("time relay returned too many timestamps")
	}
	return reply.Responses, nil
}

type query struct {
	encoded []byte
	digest  []byte
	nonce   *big.Int
}

func newQuery() (query, error) {
	raw := make([]byte, nonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return query{}, err
	}
	// A leading one bit keeps the nonce positive and full width.
	raw[0] |= nonceLeadingBit
	nonce := new(big.Int).SetBytes(raw)
	digest := sha256.Sum256(raw)
	encoded, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: digest[:], Certificates: true, Nonce: nonce}).Marshal()
	if err != nil {
		return query{}, err
	}
	return query{encoded: encoded, digest: digest[:], nonce: nonce}, nil
}

// verify authenticates one reply and names the pinned authority that signed it.
func (query query) verify(reply []byte, authorities []Authority) (string, time.Time, error) {
	token, err := timestamp.ParseResponse(reply)
	if err != nil {
		return "", time.Time{}, err
	}
	if token.HashAlgorithm != crypto.SHA256 || !bytes.Equal(token.HashedMessage, query.digest) ||
		token.Nonce == nil || token.Nonce.Cmp(query.nonce) != 0 || token.Time.IsZero() {
		return "", time.Time{}, errors.New("timestamp does not answer this query")
	}
	signed, err := pkcs7.Parse(token.RawToken)
	if err != nil {
		return "", time.Time{}, err
	}
	if len(signed.Certificates) == 0 {
		return "", time.Time{}, errors.New("timestamp carries no signer certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range signed.Certificates {
		intermediates.AddCert(certificate)
	}
	for _, authority := range authorities {
		// No local date is trusted yet, so certificate dates are judged at the
		// signed time: a timestamp outside its signer's validity is rejected.
		if signed.VerifyWithOpts(x509.VerifyOptions{Roots: authority.Roots, Intermediates: intermediates,
			CurrentTime: token.Time, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}) == nil {
			return authority.Name, token.Time, nil
		}
	}
	return "", time.Time{}, errors.New("timestamp is not signed by a pinned authority")
}

// agree returns the median authority time once enough authorities fall
// within tolerance of it. One wrong authority can therefore shift the result
// by at most the tolerance.
func agree(issued map[string]time.Time, tolerance time.Duration) (time.Time, []string, error) {
	names := make([]string, 0, len(issued))
	for name := range issued {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if !issued[names[i]].Equal(issued[names[j]]) {
			return issued[names[i]].Before(issued[names[j]])
		}
		return names[i] < names[j]
	})
	if len(names) < RequiredAuthorities {
		return time.Time{}, nil, fmt.Errorf("%d of %d required timestamp authorities answered", len(names), RequiredAuthorities)
	}
	median := issued[names[len(names)/2]]
	var agreeing []string
	for _, name := range names {
		if issued[name].Sub(median).Abs() <= tolerance {
			agreeing = append(agreeing, name)
		}
	}
	if len(agreeing) < RequiredAuthorities {
		return time.Time{}, nil, errors.New("timestamp authorities disagree")
	}
	sort.Strings(agreeing)
	return median, agreeing, nil
}
