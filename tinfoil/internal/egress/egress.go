package egress

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/netutil"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
	"tinfoil/internal/containernet"
	"tinfoil/internal/runtimeconfig"
)

const (
	queryTimeout         = 5 * time.Second
	upstreamTimeout      = 2 * time.Second
	idleTimeout          = 10 * time.Second
	maxConcurrentQueries = 64
	// Datagrams a network may send per second before the rest are dropped.
	maxDatagramRate = 512
	maxAnswerTTL    = uint32(3600)
	maxCNAMEs       = 16
	replyGrace      = 5 * time.Second
	upstreamName    = "one.one.one.one"
)

var upstreamAddresses = []string{"1.1.1.1:853", "1.0.0.1:853"}

type policy struct {
	name   string
	prefix netip.Prefix
	*runtimeconfig.NetworkSpec
	generation uint32
}

type cacheKey struct {
	network string
	name    string
}

type slotKey struct {
	network string
	tcp     bool
}

var guestPolicy = &policy{NetworkSpec: &runtimeconfig.NetworkSpec{Egress: "open"}}

type cachedAnswer struct {
	mu      sync.Mutex
	answer  *dns.Msg
	expires time.Time
}

type Engine struct {
	exchange            func(context.Context, *dns.Msg) (*dns.Msg, error)
	nft                 func(context.Context, string) ([]byte, error)
	listSet             func(context.Context, string) ([]byte, error)
	loadPolicies        func(uint32) ([]policy, error)
	allocatedGeneration func() (uint32, error)
	now                 func() time.Time
	mu                  sync.Mutex
	firewall            sync.Mutex
	policies            []policy
	generation          uint32
	cache               map[cacheKey]*cachedAnswer
	slots               sync.Map
	datagrams           sync.Map
}

func New() *Engine {
	return &Engine{
		exchange: exchangeTLS,
		nft: func(ctx context.Context, script string) ([]byte, error) {
			command := exec.CommandContext(ctx, "nft", "-f", "-")
			command.Stdin = strings.NewReader(script)
			return command.Output()
		},
		listSet: func(ctx context.Context, name string) ([]byte, error) {
			return exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "tinfoil", name).Output()
		},
		loadPolicies:        loadPolicies,
		allocatedGeneration: allocatedGeneration,
		now:                 time.Now,
		cache:               make(map[cacheKey]*cachedAnswer),
	}
}

func (e *Engine) Run(ctx context.Context) error {
	var servers []*dns.Server
	// The readiness address is bound last, so it implies both are listening.
	for _, listener := range []struct {
		address string
		handler dns.Handler
	}{
		{containernet.DNSContainerAddress, e},
		{containernet.DNSReadyAddress, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) { e.serve(w, request, guestPolicy) })},
	} {
		address, handler := listener.address, listener.handler
		tcp, err := net.Listen("tcp4", address)
		if err != nil {
			return err
		}
		defer tcp.Close()
		udp, err := net.ListenPacket("udp4", address)
		if err != nil {
			return err
		}
		defer udp.Close()
		limited := netutil.LimitListener(tcp, maxConcurrentQueries)
		if handler == e {
			limited = &sourceListener{tcp, e}
		}
		datagrams := &dns.Server{PacketConn: udp, Handler: handler, UDPSize: dns.MaxMsgSize, WriteTimeout: queryTimeout}
		if handler == e {
			datagrams.DecorateReader = func(reader dns.Reader) dns.Reader { return &sourceReader{reader, e} }
		}
		servers = append(servers,
			&dns.Server{Listener: limited, Handler: handler, ReadTimeout: queryTimeout, WriteTimeout: queryTimeout, IdleTimeout: func() time.Duration { return idleTimeout }},
			datagrams,
		)
	}
	errors := make(chan error, len(servers))
	for _, server := range servers {
		go func() { errors <- server.ActivateAndServe() }()
		defer server.Shutdown()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errors:
		return err
	}
}

// sourceListener bounds each network's connections so one workload cannot
// occupy the listener for the others.
type sourceListener struct {
	net.Listener
	engine *Engine
}

type sourceConn struct {
	net.Conn
	release func()
}

func (l *sourceListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if remote, err := netip.ParseAddrPort(connection.RemoteAddr().String()); err == nil {
			if p, err := l.engine.policyFor(remote.Addr().Unmap()); err == nil && p != nil {
				if release, ok := l.engine.acquire(slotKey{p.name, true}); ok {
					return &sourceConn{connection, sync.OnceFunc(release)}, nil
				}
			}
		}
		connection.Close()
	}
}

// sourceReader drops a network's datagrams beyond its rate before the server
// starts any work for them.
type sourceReader struct {
	dns.Reader
	engine *Engine
}

func (r *sourceReader) ReadUDP(connection *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	for {
		message, session, err := r.Reader.ReadUDP(connection, timeout)
		if err != nil || r.engine.admit(session.RemoteAddr()) {
			return message, session, err
		}
	}
}

// admit counts sources without a readable policy together, so they are still
// answered with the reason, at a bounded rate.
func (e *Engine) admit(source net.Addr) bool {
	network := ""
	if remote, err := netip.ParseAddrPort(source.String()); err == nil {
		// Only the policy already in memory is consulted before the limit.
		e.mu.Lock()
		p, err := e.match(remote.Addr().Unmap())
		e.mu.Unlock()
		if err == nil && p != nil {
			network = p.name
		}
	}
	value, ok := e.datagrams.Load(network)
	if !ok {
		value, _ = e.datagrams.LoadOrStore(network, rate.NewLimiter(maxDatagramRate, maxDatagramRate))
	}
	return value.(*rate.Limiter).AllowN(e.now(), 1)
}

func (c *sourceConn) Close() error {
	c.release()
	return c.Conn.Close()
}

func (e *Engine) acquire(key slotKey) (func(), bool) {
	value, ok := e.slots.Load(key)
	if !ok {
		value, _ = e.slots.LoadOrStore(key, make(chan struct{}, maxConcurrentQueries))
	}
	slots := value.(chan struct{})
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		return nil, false
	}
}

func (e *Engine) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	e.serve(w, request, nil)
}

func (e *Engine) serve(w dns.ResponseWriter, request *dns.Msg, p *policy) {
	reply := new(dns.Msg).SetRcode(request, dns.RcodeServerFailure)
	defer func() {
		if failure := recover(); failure != nil {
			log.Printf("DNS query failed: %v", failure)
			reply = new(dns.Msg).SetRcode(request, dns.RcodeServerFailure)
		}
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			size := dns.MinMsgSize
			if opt := request.IsEdns0(); opt != nil {
				size = max(size, int(opt.UDPSize()))
			}
			reply.Truncate(size)
		}
		_ = w.WriteMsg(reply)
	}()
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 || request.Question[0].Qclass != dns.ClassINET {
		reply.Rcode = dns.RcodeFormatError
		return
	}
	question := request.Question[0]
	if question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		reply.Rcode = dns.RcodeRefused
		return
	}
	if p == nil {
		remote, err := netip.ParseAddrPort(w.RemoteAddr().String())
		if err != nil {
			return
		}
		p, err = e.policyFor(remote.Addr().Unmap())
		if err != nil {
			log.Printf("DNS policy unavailable: %v", err)
			return
		}
		if p == nil {
			reply.Rcode = dns.RcodeRefused
			return
		}
	}
	if p.Egress != "open" && (p.Egress != "allowlist" || !allowed(question.Name, p.Allow)) {
		reply.Rcode = dns.RcodeNameError
		return
	}
	if p.Egress == "allowlist" && question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		reply.Rcode = dns.RcodeRefused
		return
	}
	if p.Egress == "allowlist" && question.Qtype == dns.TypeAAAA {
		reply.Rcode = dns.RcodeSuccess
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	// Rebuild the question so client-supplied records and EDNS options never
	// become upstream instructions or firewall input.
	query := new(dns.Msg).SetQuestion(question.Name, question.Qtype)
	var answer *dns.Msg
	var err error
	if p.Egress == "allowlist" {
		answer, err = e.resolveAllowed(ctx, query, p)
	} else if release, ok := e.acquire(slotKey{network: p.name}); ok {
		defer release()
		answer, err = e.exchange(ctx, query)
	} else {
		return
	}
	if err != nil {
		return
	}
	answer.Id = request.Id
	answer.Question = request.Question
	answer.RecursionDesired = request.RecursionDesired
	reply = answer
}

func (e *Engine) resolveAllowed(ctx context.Context, query *dns.Msg, p *policy) (*dns.Msg, error) {
	network := p.name
	key := cacheKey{network, dns.CanonicalName(query.Question[0].Name)}
	e.mu.Lock()
	entry := e.cache[key]
	if entry == nil {
		// Only allowlisted A queries reach this cache, bounding it by the policy.
		entry = &cachedAnswer{}
		e.cache[key] = entry
	}
	e.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if !entry.fresh(e.now()) {
		// Only the lookup that reaches the upstream resolver counts against
		// the network; requests waiting for its answer do not.
		release, ok := e.acquire(slotKey{network: network})
		if !ok {
			return nil, fmt.Errorf("too many DNS lookups for network %s", network)
		}
		defer release()
		answer, err := e.exchange(ctx, query)
		if err != nil {
			return nil, err
		}
		received := e.now()
		answer, err = e.authorizedAnswer(ctx, query, answer, p)
		if err != nil {
			return nil, err
		}
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) == 0 {
			return answer, nil
		}
		entry.answer = answer
		entry.expires = received.Add(time.Duration(answer.Answer[0].Header().Ttl) * time.Second)
	}
	return entry.remaining(e.now()), nil
}

func (c *cachedAnswer) fresh(now time.Time) bool {
	return c.answer != nil && now.Before(c.expires)
}

func (c *cachedAnswer) remaining(now time.Time) *dns.Msg {
	answer := c.answer.Copy()
	ttl := uint32(max(0, c.expires.Sub(now)/time.Second))
	for _, record := range answer.Answer {
		record.Header().Ttl = ttl
	}
	return answer
}

func allowed(name string, domains []string) bool {
	for _, domain := range domains {
		if dns.CanonicalName(name) == dns.CanonicalName(domain) {
			return true
		}
	}
	return false
}

func (e *Engine) policyFor(source netip.Addr) (*policy, error) {
	// A new generation is allocated before the firewall is replaced, so no
	// query is answered from a policy older than the installed one.
	generation, err := e.allocatedGeneration()
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// Generations only grow, so a query that read an older one never
	// replaces a newer policy.
	if e.policies == nil || generation > e.generation {
		policies, err := e.loadPolicies(generation)
		if err != nil {
			return nil, err
		}
		// Cached answers hold permissions in the sets of the policy they
		// were resolved under.
		e.policies, e.generation, e.cache = policies, generation, make(map[cacheKey]*cachedAnswer)
	}
	return e.match(source)
}

// match selects among the loaded policies; the caller holds e.mu.
func (e *Engine) match(source netip.Addr) (*policy, error) {
	var matched *policy
	for i := range e.policies {
		p := &e.policies[i]
		if p.prefix.Contains(source) {
			if matched != nil {
				return nil, fmt.Errorf("ambiguous DNS source network")
			}
			matched = p
		}
	}
	return matched, nil
}

func allocatedGeneration() (uint32, error) {
	data, err := os.ReadFile(boot.NetworkGenerationPath)
	if err != nil {
		return 0, err
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	return uint32(generation), err
}

func loadPolicies(generation uint32) ([]policy, error) {
	data, err := os.ReadFile(boot.RuntimeConfigPath)
	if err != nil {
		return nil, err
	}
	return parsePolicies(data, generation)
}

func parsePolicies(data []byte, generation uint32) ([]policy, error) {
	var config runtimeconfig.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	policies := make([]policy, 0, len(config.Networks))
	for name, network := range config.Networks {
		if network == nil {
			network = &runtimeconfig.NetworkSpec{Egress: "closed"}
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, err
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, err
			}
			if prefix.Addr().Is4() {
				policies = append(policies, policy{name, prefix.Masked(), network, generation})
			}
		}
	}
	return policies, nil
}

func exchangeTLS(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Net: "tcp-tls", Timeout: upstreamTimeout, TLSConfig: &tls.Config{ServerName: upstreamName, MinVersion: tls.VersionTLS12}}
	var lastErr error
	for _, address := range upstreamAddresses {
		answer, _, err := client.ExchangeContext(ctx, query, address)
		if err == nil && len(answer.Question) == 1 &&
			dns.CanonicalName(answer.Question[0].Name) == dns.CanonicalName(query.Question[0].Name) &&
			answer.Question[0].Qtype == query.Question[0].Qtype && answer.Question[0].Qclass == dns.ClassINET && !answer.Truncated {
			return answer, nil
		}
		lastErr = fmt.Errorf("invalid or unavailable upstream DNS answer: %v", err)
	}
	return nil, lastErr
}

func (e *Engine) authorizedAnswer(ctx context.Context, query, answer *dns.Msg, p *policy) (*dns.Msg, error) {
	reply := new(dns.Msg).SetReply(query)
	reply.RecursionAvailable = true
	name := dns.CanonicalName(query.Question[0].Name)
	ttl := maxAnswerTTL
	seen := map[string]bool{}
	for depth := 0; depth < maxCNAMEs; depth++ {
		if seen[name] {
			return nil, fmt.Errorf("cyclic DNS alias")
		}
		seen[name] = true
		if answer.Rcode != dns.RcodeSuccess {
			reply.Rcode = answer.Rcode
			return reply, nil
		}
		var alias *dns.CNAME
		var addresses []*dns.A
		for _, record := range answer.Answer {
			if record.Header().Class != dns.ClassINET || dns.CanonicalName(record.Header().Name) != name {
				continue
			}
			switch record := record.(type) {
			case *dns.CNAME:
				if alias != nil && !strings.EqualFold(alias.Target, record.Target) {
					return nil, fmt.Errorf("conflicting DNS aliases")
				}
				alias = record
			case *dns.A:
				addr, ok := netip.AddrFromSlice(record.A)
				if !ok || !publicIPv4(addr.Unmap()) {
					return nil, fmt.Errorf("non-public DNS answer")
				}
				addresses = append(addresses, record)
			}
		}
		if alias != nil {
			if len(addresses) != 0 {
				return nil, fmt.Errorf("DNS alias has address records")
			}
			ttl = min(ttl, alias.Hdr.Ttl)
			copy := dns.Copy(alias)
			copy.Header().Ttl = min(copy.Header().Ttl, maxAnswerTTL)
			reply.Answer = append(reply.Answer, copy)
			name = dns.CanonicalName(alias.Target)
			found := false
			for _, record := range answer.Answer {
				if dns.CanonicalName(record.Header().Name) == name {
					found = true
					break
				}
			}
			if !found {
				var err error
				answer, err = e.exchange(ctx, new(dns.Msg).SetQuestion(name, dns.TypeA))
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		leases := map[string]uint32{}
		for _, address := range addresses {
			ttl = min(ttl, address.Hdr.Ttl)
		}
		for _, record := range reply.Answer {
			record.Header().Ttl = ttl
		}
		for _, address := range addresses {
			copy := dns.Copy(address).(*dns.A)
			copy.Hdr.Ttl = min(ttl, copy.Hdr.Ttl)
			reply.Answer = append(reply.Answer, copy)
			leases[copy.A.String()] = max(leases[copy.A.String()], copy.Hdr.Ttl)
		}
		if err := e.install(ctx, p, leases); err != nil {
			return nil, err
		}
		return reply, nil
	}
	return nil, fmt.Errorf("too many DNS aliases")
}

func (e *Engine) install(ctx context.Context, p *policy, leases map[string]uint32) error {
	if len(leases) == 0 {
		return nil
	}
	// Firewall updates are serialized on their own, so policy lookups never
	// wait for one.
	e.firewall.Lock()
	defer e.firewall.Unlock()
	set := containernet.AllowSetPrefix + p.name
	data, err := e.listSet(ctx, set)
	if err != nil {
		return err
	}
	// Read remaining kernel lifetimes so concurrent answers and resolver
	// restarts cannot shorten an address lease already delivered to a client.
	var state struct {
		NFTables []struct {
			Set struct {
				Elements []struct {
					Element struct {
						Value   string `json:"val"`
						Expires uint32 `json:"expires"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	addresses := make([]string, 0, len(leases))
	for address, ttl := range leases {
		leases[address] = ttl + uint32(replyGrace/time.Second)
		addresses = append(addresses, address)
	}
	slices.Sort(addresses)
	for _, entry := range state.NFTables {
		for _, element := range entry.Set.Elements {
			if ttl, ok := leases[element.Element.Value]; ok {
				leases[element.Element.Value] = max(ttl, element.Element.Expires+1)
			}
		}
	}
	var script strings.Builder
	// Removing the generation fails the whole update unless the policy this
	// answer was authorized under is still the installed one.
	fmt.Fprintf(&script, "delete element inet tinfoil %[1]s { %[2]d }\nadd element inet tinfoil %[1]s { %[2]d }\n", containernet.PolicyGenerationSet, p.generation)
	for _, address := range addresses {
		fmt.Fprintf(&script, "destroy element inet tinfoil %s { %s }\nadd element inet tinfoil %s { %s timeout %ds }\n", set, address, set, address, leases[address])
	}
	_, err = e.nft(ctx, script.String())
	return err
}

func publicIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	for _, prefix := range nonPublicIPv4Prefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var nonPublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
}
