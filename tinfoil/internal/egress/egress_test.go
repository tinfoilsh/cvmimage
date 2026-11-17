package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"tinfoil/internal/runtimeconfig"
)

type responseWriter struct {
	dns.ResponseWriter
	source string
	answer *dns.Msg
	write  func(*dns.Msg)
	read   func()
}

func (w *responseWriter) RemoteAddr() net.Addr {
	if w.read != nil {
		w.read()
	}
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(w.source))
}
func (w *responseWriter) WriteMsg(m *dns.Msg) error {
	w.answer = m.Copy()
	if w.write != nil {
		w.write(m)
	}
	return nil
}

func testEngine(t *testing.T, records ...string) (*Engine, *[]string) {
	t.Helper()
	e := New()
	e.now = func() time.Time { return time.Unix(0, 0) }
	policies := []policy{
		{"alpha", netip.MustParsePrefix("10.42.0.0/24"), &runtimeconfig.NetworkSpec{Egress: "allowlist", Allow: []string{"storage.example"}}, 7},
		{"beta", netip.MustParsePrefix("10.43.0.0/24"), &runtimeconfig.NetworkSpec{Egress: "allowlist", Allow: []string{"other.example"}}, 7},
		{"closed", netip.MustParsePrefix("10.44.0.0/24"), &runtimeconfig.NetworkSpec{Egress: "closed"}, 7},
		{"open", netip.MustParsePrefix("10.45.0.0/24"), &runtimeconfig.NetworkSpec{Egress: "open"}, 7},
	}
	e.policies, e.generation = policies, 7
	e.allocatedGeneration = func() (uint32, error) { return 7, nil }
	e.loadPolicies = func(uint32) ([]policy, error) { return policies, nil }
	e.exchange = func(_ context.Context, query *dns.Msg) (*dns.Msg, error) {
		answer := new(dns.Msg).SetReply(query)
		for _, record := range records {
			rr, err := dns.NewRR(record)
			if err != nil {
				t.Fatal(err)
			}
			answer.Answer = append(answer.Answer, rr)
		}
		return answer, nil
	}
	var scripts []string
	e.nft = func(_ context.Context, script string) ([]byte, error) {
		scripts = append(scripts, script)
		return []byte(`{"nftables":[]}`), nil
	}
	e.listSet = func(ctx context.Context, set string) ([]byte, error) {
		return e.nft(ctx, "list set inet tinfoil "+set+"\n")
	}
	return e, &scripts
}

func ask(e *Engine, source, name string, kind uint16) *dns.Msg {
	w := &responseWriter{source: source}
	e.ServeDNS(w, new(dns.Msg).SetQuestion(name, kind))
	return w.answer
}

func askGuest(e *Engine, name string, kind uint16) *dns.Msg {
	w := &responseWriter{source: "127.0.0.1:12345"}
	e.serve(w, new(dns.Msg).SetQuestion(name, kind), guestPolicy)
	return w.answer
}

func TestDNSInstallsRotatingAnswersBeforeReply(t *testing.T) {
	e, scripts := testEngine(t)
	now := e.now()
	e.now = func() time.Time { return now }
	for _, address := range []string{"8.8.8.8", "8.8.4.4"} {
		e.exchange = func(_ context.Context, query *dns.Msg) (*dns.Msg, error) {
			answer := new(dns.Msg).SetReply(query)
			rr, _ := dns.NewRR("storage.example. 30 IN A " + address)
			answer.Answer = []dns.RR{rr}
			return answer, nil
		}
		w := &responseWriter{source: "10.42.0.2:12345", write: func(reply *dns.Msg) {
			if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
				t.Fatalf("reply = %v", reply)
			}
			if len(*scripts) < 2 || !strings.Contains((*scripts)[len(*scripts)-1], "allow-alpha { "+address+" timeout 35s }") {
				t.Fatalf("answer returned before its address was installed: %v", *scripts)
			}
		}}
		e.ServeDNS(w, new(dns.Msg).SetQuestion("StOrAgE.Example.", dns.TypeA))
		now = now.Add(30 * time.Second)
	}
	for _, script := range *scripts {
		if strings.Contains(script, "flush") || strings.Contains(script, "allow-beta") {
			t.Fatalf("unrelated permissions changed: %s", script)
		}
	}
}

func TestDNSPolicyRejectsBeforeUpstream(t *testing.T) {
	for _, tc := range []struct {
		name, source, domain string
		kind                 uint16
		code                 int
	}{
		{"wrong network", "10.43.0.2:12345", "storage.example.", dns.TypeA, dns.RcodeNameError},
		{"closed", "10.44.0.2:12345", "storage.example.", dns.TypeA, dns.RcodeNameError},
		{"unknown network", "10.46.0.2:12345", "storage.example.", dns.TypeA, dns.RcodeRefused},
		{"subdomain", "10.42.0.2:12345", "secret.storage.example.", dns.TypeA, dns.RcodeNameError},
		{"suffix", "10.42.0.2:12345", "storage.example.attacker.", dns.TypeA, dns.RcodeNameError},
		{"txt", "10.42.0.2:12345", "storage.example.", dns.TypeTXT, dns.RcodeRefused},
		{"ipv6", "10.42.0.2:12345", "storage.example.", dns.TypeAAAA, dns.RcodeSuccess},
		{"zone transfer", "10.45.0.2:12345", "example.", dns.TypeAXFR, dns.RcodeRefused},
		{"loopback on the workload address", "127.0.0.1:12345", "example.", dns.TypeA, dns.RcodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, scripts := testEngine(t)
			e.exchange = func(context.Context, *dns.Msg) (*dns.Msg, error) {
				t.Fatal("rejected query leaked upstream")
				return nil, nil
			}
			answer := ask(e, tc.source, tc.domain, tc.kind)
			if answer.Rcode != tc.code || len(answer.Answer) != 0 || len(*scripts) != 0 {
				t.Fatalf("answer=%v scripts=%v", answer, *scripts)
			}
		})
	}
}

func TestDNSCNAMEAndUnrelatedRecords(t *testing.T) {
	e, scripts := testEngine(t,
		"storage.example. 120 IN CNAME shard.example.",
		"shard.example. 30 IN A 8.8.8.8",
		"unrelated.example. 30 IN A 9.9.9.9",
	)
	answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA)
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 2 {
		t.Fatalf("answer=%v", answer)
	}
	for _, rr := range answer.Answer {
		if rr.Header().Ttl != 30 {
			t.Fatalf("alias outlives address: %v", answer)
		}
	}
	if joined := strings.Join(*scripts, ""); strings.Contains(joined, "9.9.9.9") || !strings.Contains(joined, "8.8.8.8 timeout 35s") {
		t.Fatalf("scripts=%s", joined)
	}
}

func TestDNSRejectsUnsafeAnswersAndFirewallFailures(t *testing.T) {
	for name, records := range map[string][]string{
		"private":           {"storage.example. 30 IN A 10.0.0.1"},
		"mixed private":     {"storage.example. 30 IN A 8.8.8.8", "storage.example. 30 IN A 127.0.0.1"},
		"private alias":     {"storage.example. 30 IN CNAME internal.example.", "internal.example. 30 IN A 169.254.169.254"},
		"cycle":             {"storage.example. 30 IN CNAME other.example.", "other.example. 30 IN CNAME storage.example."},
		"conflicting alias": {"storage.example. 30 IN CNAME one.example.", "storage.example. 30 IN CNAME two.example."},
		"alias and address": {"storage.example. 30 IN CNAME one.example.", "storage.example. 30 IN A 8.8.8.8"},
	} {
		t.Run(name, func(t *testing.T) {
			e, scripts := testEngine(t, records...)
			answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA)
			if answer.Rcode != dns.RcodeServerFailure || len(answer.Answer) != 0 || len(*scripts) != 0 {
				t.Fatalf("answer=%v scripts=%v", answer, *scripts)
			}
		})
	}
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("firewall operation %d", failAt), func(t *testing.T) {
			e, _ := testEngine(t, "storage.example. 30 IN A 8.8.8.8")
			calls := 0
			e.nft = func(context.Context, string) ([]byte, error) {
				calls++
				if calls == failAt {
					return nil, errors.New("firewall unavailable")
				}
				return []byte(`{"nftables":[]}`), nil
			}
			answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA)
			if answer.Rcode != dns.RcodeServerFailure || len(answer.Answer) != 0 {
				t.Fatalf("answer escaped failed firewall update: %v", answer)
			}
		})
	}
}

func TestDNSPreservesExistingLeaseAcrossRestart(t *testing.T) {
	e, _ := testEngine(t, "storage.example. 1 IN A 8.8.8.8")
	e.nft = func(_ context.Context, script string) ([]byte, error) {
		if strings.HasPrefix(script, "list set") {
			return []byte(`{"nftables":[{"set":{"elem":[{"elem":{"val":"8.8.8.8","expires":120}}]}}]}`), nil
		}
		if !strings.Contains(script, "timeout 121s") {
			t.Fatalf("existing lease shortened: %s", script)
		}
		return nil, nil
	}
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
		t.Fatal(answer)
	}
}

func TestDNSFollowsSeparateAliasAnswersAndStripsClientOptions(t *testing.T) {
	e, _ := testEngine(t)
	calls := 0
	e.exchange = func(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
		calls++
		if len(q.Extra) != 0 || len(q.Answer) != 0 || len(q.Ns) != 0 {
			t.Fatalf("client records forwarded: %v", q)
		}
		r := new(dns.Msg).SetReply(q)
		text := "storage.example. 30 IN CNAME shard.example."
		if calls == 2 {
			if q.Question[0].Name != "shard.example." {
				t.Fatal(q)
			}
			text = "shard.example. 10 IN A 8.8.8.8"
		}
		rr, _ := dns.NewRR(text)
		r.Answer = []dns.RR{rr}
		return r, nil
	}
	q := new(dns.Msg).SetQuestion("storage.example.", dns.TypeA)
	q.SetEdns0(dns.DefaultMsgSize, true)
	spoofed, _ := dns.NewRR("storage.example. 30 IN A 10.0.0.1")
	q.Answer = []dns.RR{spoofed}
	authority, _ := dns.NewRR("example. 30 IN NS ns.attacker.")
	q.Ns = []dns.RR{authority}
	w := &responseWriter{source: "10.42.0.2:12345"}
	e.ServeDNS(w, q)
	if calls != 2 || w.answer.Rcode != dns.RcodeSuccess || len(w.answer.Answer) != 2 {
		t.Fatalf("calls=%d answer=%v", calls, w.answer)
	}
}

func TestDNSGuestAndOpenNetworksDoNotGrantFirewallAccess(t *testing.T) {
	for _, guest := range []bool{true, false} {
		for kind, record := range map[uint16]string{dns.TypeA: "other.example. 30 IN A 8.8.8.8", dns.TypeTXT: "other.example. 30 IN TXT hello"} {
			e, scripts := testEngine(t, record)
			answer := ask(e, "10.45.0.2:12345", "other.example.", kind)
			if guest {
				answer = askGuest(e, "other.example.", kind)
			}
			if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 || len(*scripts) != 0 {
				t.Fatalf("answer=%v scripts=%v", answer, *scripts)
			}
		}
	}
}

func TestPublicIPv4RejectsNonPublicAnswers(t *testing.T) {
	for _, value := range []string{"10.0.0.1", "192.0.0.8", "192.0.0.9", "192.0.0.10", "192.0.2.1", "224.0.0.1", "2001:db8::1"} {
		if publicIPv4(netip.MustParseAddr(value)) {
			t.Errorf("publicIPv4(%s) = true", value)
		}
	}
	if !publicIPv4(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
}

func TestDNSOverTLSRejectsUntrustedResolver(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	config := certificateServer.TLS.Clone()
	certificateServer.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &dns.Server{
		Listener:          listener,
		NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			answer := new(dns.Msg).SetReply(q)
			record, _ := dns.NewRR("storage.example. 30 IN A 8.8.8.8")
			answer.Answer = []dns.RR{record}
			_ = w.WriteMsg(answer)
		}),
	}
	go server.ActivateAndServe()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	previous := upstreamAddresses
	upstreamAddresses = []string{listener.Addr().String()}
	t.Cleanup(func() { upstreamAddresses = previous })
	if answer, err := exchangeTLS(context.Background(), new(dns.Msg).SetQuestion("storage.example.", dns.TypeA)); err == nil || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("untrusted resolver not rejected by certificate verification: answer=%v err=%v", answer, err)
	}
}

func TestDNSTreatsNetworksWithoutSettingsAsClosed(t *testing.T) {
	policies, err := parsePolicies([]byte("networks:\n  lo:\n"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) == 0 {
		t.Fatal("loopback network has no policy")
	}
	policies[0].prefix = netip.MustParsePrefix("10.50.0.0/24")
	e, scripts := testEngine(t, "storage.example. 30 IN A 8.8.8.8")
	e.policies = policies[:1]
	exchanged := false
	exchange := e.exchange
	e.exchange = func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
		exchanged = true
		return exchange(ctx, query)
	}
	answer := ask(e, "10.50.0.2:12345", "storage.example.", dns.TypeA)
	if answer.Rcode != dns.RcodeNameError || exchanged || len(*scripts) != 0 {
		t.Fatalf("answer=%v exchanged=%v scripts=%v", answer, exchanged, *scripts)
	}
}

func TestDNSAnswersFailureWhenQueryHandlingPanics(t *testing.T) {
	e, _ := testEngine(t)
	upstream := e.exchange
	e.exchange = func(context.Context, *dns.Msg) (*dns.Msg, error) { panic("unexpected upstream state") }
	for _, source := range []string{"10.45.0.2:12345", "10.43.0.2:12345"} {
		for range maxConcurrentQueries + 1 {
			answer := ask(e, source, "other.example.", dns.TypeA)
			if answer == nil || answer.Rcode != dns.RcodeServerFailure {
				t.Fatalf("answer=%v", answer)
			}
		}
	}
	e.exchange = upstream
	for _, source := range []string{"10.45.0.2:12345", "10.43.0.2:12345"} {
		if answer := ask(e, source, "other.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
			t.Fatalf("failed lookups kept their capacity: %v", answer)
		}
	}
}

func TestDNSRequestsWaitingForOneNameLeaveCapacityForOthers(t *testing.T) {
	e, _ := testEngine(t, "storage.example. 60 IN A 8.8.8.8", "second.example. 60 IN A 8.8.4.4")
	e.policies[0].Allow = []string{"storage.example", "second.example"}
	upstream := e.exchange
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	e.exchange = func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
		if query.Question[0].Name == "storage.example." {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
		}
		return upstream(ctx, query)
	}
	done := make(chan *dns.Msg, 2*maxConcurrentQueries)
	for range 2 * maxConcurrentQueries {
		go func() { done <- ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA) }()
	}
	<-started
	if answer := ask(e, "10.42.0.3:12345", "second.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("requests for one name used the network's capacity: %v", answer)
	}
	close(release)
	for range 2 * maxConcurrentQueries {
		if answer := <-done; answer.Rcode != dns.RcodeSuccess {
			t.Fatalf("waiting request failed: %v", answer)
		}
	}
}

func TestDNSLookupCapacityIsSeparatePerSource(t *testing.T) {
	e, _ := testEngine(t, "storage.example. 60 IN A 8.8.8.8")
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
		t.Fatal(answer)
	}
	upstream := e.exchange
	started := make(chan struct{}, maxConcurrentQueries)
	release := make(chan struct{})
	e.exchange = func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
		if query.Question[0].Name == "slow.example." {
			started <- struct{}{}
			<-release
		}
		return upstream(ctx, query)
	}
	done := make(chan struct{}, maxConcurrentQueries)
	for range maxConcurrentQueries {
		go func() {
			ask(e, "10.45.0.2:12345", "slow.example.", dns.TypeA)
			done <- struct{}{}
		}()
	}
	for range maxConcurrentQueries {
		<-started
	}
	if answer := ask(e, "10.45.0.3:12345", "other.example.", dns.TypeA); answer.Rcode != dns.RcodeServerFailure {
		t.Fatalf("network exceeded its lookup capacity: %v", answer)
	}
	if answer := askGuest(e, "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("guest lookup was starved: %v", answer)
	}
	if answer := ask(e, "10.43.0.2:12345", "other.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("other network lookup was starved: %v", answer)
	}
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatalf("cached answer was not served: %v", answer)
	}
	close(release)
	for range maxConcurrentQueries {
		<-done
	}
}

func TestDNSDatagramRateIsSeparatePerNetwork(t *testing.T) {
	e, _ := testEngine(t)
	now := e.now()
	e.now = func() time.Time { return now }
	flooding := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.45.0.2:12345"))
	for range maxDatagramRate {
		if !e.admit(flooding) {
			t.Fatal("datagram within the network's rate was dropped")
		}
	}
	if e.admit(flooding) {
		t.Fatal("datagram beyond the network's rate was admitted")
	}
	if e.admit(net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.45.0.3:12345"))) {
		t.Fatal("another address in the flooding network had its own rate")
	}
	for _, source := range []string{"10.42.0.2:12345", "10.46.0.2:12345"} {
		if !e.admit(net.UDPAddrFromAddrPort(netip.MustParseAddrPort(source))) {
			t.Fatalf("flood from another network dropped a datagram from %s", source)
		}
	}
	now = now.Add(time.Second)
	if !e.admit(flooding) {
		t.Fatal("network did not regain its rate")
	}
}

func TestDNSAppliesReplacedPolicyOnTheNextQuery(t *testing.T) {
	e, scripts := testEngine(t, "storage.example. 60 IN A 8.8.8.8")
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess {
		t.Fatal(answer)
	}
	if script := (*scripts)[1]; !strings.HasPrefix(script, "delete element inet tinfoil policy-generation { 7 }\nadd element inet tinfoil policy-generation { 7 }\n") {
		t.Fatalf("permission does not require its policy generation: %s", script)
	}
	allowed := map[uint32]string{8: "other.example", 9: "storage.example"}
	e.loadPolicies = func(generation uint32) ([]policy, error) {
		return []policy{{"alpha", netip.MustParsePrefix("10.42.0.0/24"), &runtimeconfig.NetworkSpec{Egress: "allowlist", Allow: []string{allowed[generation]}}, generation}}, nil
	}
	e.allocatedGeneration = func() (uint32, error) { return 8, nil }
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeNameError {
		t.Fatalf("removed name still resolves: %v", answer)
	}
	e.allocatedGeneration = func() (uint32, error) { return 9, nil }
	if answer := ask(e, "10.42.0.2:12345", "storage.example.", dns.TypeA); answer.Rcode != dns.RcodeSuccess || len(*scripts) != 4 || !strings.Contains((*scripts)[3], "policy-generation { 9 }") {
		t.Fatalf("answer cached under a replaced policy was reused: %v scripts=%v", answer, *scripts)
	}
}
