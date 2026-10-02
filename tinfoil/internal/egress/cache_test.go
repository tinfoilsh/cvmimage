package egress

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSCacheSharesExpirationAcrossWorkloads(t *testing.T) {
	e, scripts := testEngine(t,
		"storage.example. 120 IN CNAME shard.example.",
		"shard.example. 60 IN A 8.8.8.8",
	)
	now := e.now()
	e.now = func() time.Time { return now }
	upstream := e.exchange
	queries := 0
	e.exchange = func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
		queries++
		return upstream(ctx, query)
	}
	first := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA)
	for _, elapsed := range []time.Duration{20 * time.Second, 39 * time.Second} {
		now = now.Add(elapsed)
		answer := ask(e, "10.42.0.3:12345", "StOrAgE.Example.", dns.TypeA)
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 2 {
			t.Fatalf("cached answer = %v", answer)
		}
		remaining := uint32(60 - now.Unix())
		for _, record := range answer.Answer {
			if record.Header().Ttl != remaining {
				t.Fatalf("cached TTL = %d, want %d", record.Header().Ttl, remaining)
			}
		}
	}
	if queries != 1 || len(*scripts) != 2 || first.Answer[0].Header().Ttl != 60 {
		t.Fatalf("queries=%d scripts=%v first=%v", queries, *scripts, first)
	}
	now = now.Add(time.Second)
	if answer := ask(e, "10.42.0.3:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess || answer.Answer[0].Header().Ttl != 60 {
		t.Fatalf("refreshed answer = %v", answer)
	}
	if queries != 2 || len(*scripts) != 4 {
		t.Fatalf("expired answer was not refreshed: queries=%d scripts=%v", queries, *scripts)
	}
}

func TestDNSCacheKeepsNetworkPermissionsSeparate(t *testing.T) {
	e, scripts := testEngine(t, "storage.example. 60 IN A 8.8.8.8")
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
		t.Fatal(answer)
	}
	for _, source := range []string{"10.43.0.2:12345", "10.44.0.2:12345"} {
		if answer := ask(e, source, "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeNameError || len(*scripts) != 2 {
			t.Fatalf("cache bypassed network policy: answer=%v scripts=%v", answer, *scripts)
		}
	}
	e.policies[1].Allow = []string{"storage.example"}
	if answer := ask(e, "10.43.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess || len(*scripts) != 4 || !strings.Contains((*scripts)[3], "allow-beta") {
		t.Fatalf("answer returned without its network's permission: answer=%v scripts=%v", answer, *scripts)
	}
	e.policies[0].Allow = nil
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeNameError || len(*scripts) != 4 {
		t.Fatalf("cached answer bypassed allowlist check: answer=%v scripts=%v", answer, *scripts)
	}
}

func TestDNSCacheCoalescesConcurrentQueries(t *testing.T) {
	const clients = 16
	e, scripts := testEngine(t, "storage.example. 60 IN A 8.8.8.8")
	upstream := e.exchange
	var queries atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	e.exchange = func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
		if queries.Add(1) == 1 {
			close(entered)
		}
		<-release
		return upstream(ctx, query)
	}
	results := make(chan error, clients)
	for i := range clients {
		go func() {
			query := new(dns.Msg).SetQuestion("storage.example.", dns.TypeA)
			query.Id = uint16(i)
			w := &responseWriter{source: "10.42.0.2:12345"}
			e.ServeDNS(w, query)
			if w.answer.Rcode != dns.RcodeSuccess || w.answer.Id != query.Id || len(w.answer.Answer) != 1 || w.answer.Answer[0].Header().Ttl != 60 {
				results <- fmt.Errorf("client %d answer: %v", i, w.answer)
				return
			}
			results <- nil
		}()
	}
	<-entered
	close(release)
	for range clients {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if queries.Load() != 1 || len(*scripts) != 2 {
		t.Fatalf("duplicate resolutions or permissions: queries=%d scripts=%v", queries.Load(), *scripts)
	}
}

func TestDNSCacheRetriesUncacheableAnswers(t *testing.T) {
	for _, scenario := range []string{"upstream failure", "firewall failure", "negative", "empty", "zero TTL"} {
		t.Run(scenario, func(t *testing.T) {
			e, _ := testEngine(t, "storage.example. 60 IN A 8.8.8.8")
			upstream, nft := e.exchange, e.nft
			queries := 0
			e.exchange = func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
				queries++
				answer, err := upstream(ctx, query)
				if queries == 1 {
					switch scenario {
					case "upstream failure":
						return nil, errors.New("upstream unavailable")
					case "negative":
						answer.Rcode = dns.RcodeNameError
					case "empty":
						answer.Answer = nil
					case "zero TTL":
						answer.Answer[0].Header().Ttl = 0
					}
				}
				return answer, err
			}
			e.nft = func(ctx context.Context, script string) ([]byte, error) {
				if scenario == "firewall failure" && queries == 1 {
					return nil, errors.New("firewall unavailable")
				}
				return nft(ctx, script)
			}
			first := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA)
			if strings.HasSuffix(scenario, "failure") && (first.Rcode != dns.RcodeServerFailure || len(first.Answer) != 0) {
				t.Fatalf("failure returned a usable answer: %v", first)
			}
			for range 2 {
				answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA)
				if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 || answer.Answer[0].Header().Ttl != 60 {
					t.Fatalf("retry answer = %v", answer)
				}
			}
			if queries != 2 {
				t.Fatalf("upstream queries = %d, want one retry followed by a cache hit", queries)
			}
		})
	}
}
