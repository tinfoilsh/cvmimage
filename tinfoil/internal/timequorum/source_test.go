package timequorum

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testSources() []Source {
	var sources []Source
	for _, operator := range []Operator{Canonical, Cloudflare, Netnod, PTB, SIDN} {
		pin := sha256.Sum256([]byte(operator))
		sources = append(sources, Source{Operator: operator, Servers: []string{string(operator) + ".invalid"}, SPKISHA256: []string{hex.EncodeToString(pin[:])}})
	}
	return sources
}

func TestSamplerRejectsConfigurationDowngrades(t *testing.T) {
	for _, test := range []struct {
		name  string
		alter func([]Source) []Source
	}{
		{"missing operator", func(sources []Source) []Source { return sources[:RequiredOperators] }},
		{"duplicate operator", func(sources []Source) []Source { sources[1].Operator = sources[0].Operator; return sources }},
		{"unknown operator", func(sources []Source) []Source { sources[1].Operator = "unknown"; return sources }},
		{"shared key", func(sources []Source) []Source { sources[1].SPKISHA256 = sources[0].SPKISHA256; return sources }},
		{"missing pins", func(sources []Source) []Source { sources[1].SPKISHA256 = nil; return sources }},
		{"invalid pin", func(sources []Source) []Source { sources[1].SPKISHA256 = []string{"invalid"}; return sources }},
		{"missing server", func(sources []Source) []Source { sources[1].Servers = nil; return sources }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSampler(test.alter(testSources()), []string{"https://relay.invalid"}); err == nil {
				t.Fatal("invalid operator configuration accepted")
			}
		})
	}
	if _, err := NewSampler(testSources(), nil); err == nil {
		t.Fatal("missing relay accepted")
	}
}

func TestPinnedAuthenticationIgnoresUntrustedDate(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	pin := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	worker := sourceWorker{pins: [][sha256.Size]byte{pin}}
	for _, test := range []struct {
		name      string
		date      time.Time
		hostname  string
		trusted   bool
		wantError bool
	}{
		{"uninitialized clock", time.Unix(0, 0), "127.0.0.1", true, false},
		{"future clock", time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), "127.0.0.1", true, false},
		{"wrong hostname", time.Now(), "wrong.invalid", true, true},
		{"untrusted key", time.Now(), "127.0.0.1", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := worker.tlsConfig(test.hostname)
			config.Time = func() time.Time { return test.date }
			if !test.trusted {
				config = (&sourceWorker{}).tlsConfig(test.hostname)
			}
			connection, err := tls.DialWithDialer(&net.Dialer{Timeout: sourceAttemptLimit}, "tcp", upstream.Listener.Addr().String(), config)
			if err == nil {
				connection.Close()
			}
			if (err != nil) != test.wantError {
				t.Fatalf("TLS authentication error=%v", err)
			}
		})
	}
}
