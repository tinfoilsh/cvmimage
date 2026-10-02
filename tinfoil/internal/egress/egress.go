package egress

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/netutil"
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
	maxAnswerTTL         = uint32(3600)
	maxCNAMEs            = 16
	replyGrace           = 5 * time.Second
	upstreamName         = "one.one.one.one"
)

var upstreamAddresses = []string{"1.1.1.1:853", "1.0.0.1:853"}

type policy struct {
	name   string
	prefix netip.Prefix
	*runtimeconfig.NetworkSpec
}

type cacheKey struct {
	network string
	name    string
}

type cachedAnswer struct {
	mu      sync.Mutex
	answer  *dns.Msg
	expires time.Time
}

type Engine struct {
	exchange     func(context.Context, *dns.Msg) (*dns.Msg, error)
	nft          func(context.Context, string) ([]byte, error)
	listSet      func(context.Context, string) ([]byte, error)
	loadPolicies func() ([]policy, error)
	now          func() time.Time
	mu           sync.Mutex
	policies     []policy
	cache        map[cacheKey]*cachedAnswer
	slots        chan struct{}
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
		loadPolicies: loadPolicies,
		now:          time.Now,
		cache:        make(map[cacheKey]*cachedAnswer),
		slots:        make(chan struct{}, maxConcurrentQueries),
	}
}

func (e *Engine) Run(ctx context.Context) error {
	tcp, err := net.Listen("tcp4", containernet.DNSListenAddress)
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", containernet.DNSListenAddress)
	if err != nil {
		return err
	}
	defer udp.Close()
	servers := []*dns.Server{
		{Listener: netutil.LimitListener(tcp, maxConcurrentQueries), Handler: e, ReadTimeout: queryTimeout, WriteTimeout: queryTimeout, IdleTimeout: func() time.Duration { return idleTimeout }},
		{PacketConn: udp, Handler: e, UDPSize: dns.MaxMsgSize, WriteTimeout: queryTimeout},
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

func (e *Engine) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	reply := new(dns.Msg).SetRcode(request, dns.RcodeServerFailure)
	defer func() {
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			size := dns.MinMsgSize
			if opt := request.IsEdns0(); opt != nil {
				size = max(size, int(opt.UDPSize()))
			}
			reply.Truncate(size)
		}
		_ = w.WriteMsg(reply)
	}()
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return
	}
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 || request.Question[0].Qclass != dns.ClassINET {
		reply.Rcode = dns.RcodeFormatError
		return
	}
	question := request.Question[0]
	if question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		reply.Rcode = dns.RcodeRefused
		return
	}
	remote, err := netip.ParseAddrPort(w.RemoteAddr().String())
	if err != nil {
		return
	}
	p, err := e.policyFor(remote.Addr().Unmap())
	if err != nil {
		return
	}
	if p == nil {
		reply.Rcode = dns.RcodeRefused
		return
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
	if p.Egress == "allowlist" {
		answer, err = e.resolveAllowed(ctx, query, p.name)
	} else {
		answer, err = e.exchange(ctx, query)
	}
	if err != nil {
		return
	}
	answer.Id = request.Id
	answer.Question = request.Question
	answer.RecursionDesired = request.RecursionDesired
	reply = answer
}

func (e *Engine) resolveAllowed(ctx context.Context, query *dns.Msg, network string) (*dns.Msg, error) {
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
	if entry.answer == nil || !e.now().Before(entry.expires) {
		answer, err := e.exchange(ctx, query)
		if err != nil {
			return nil, err
		}
		received := e.now()
		answer, err = e.authorizedAnswer(ctx, query, answer, network)
		if err != nil {
			return nil, err
		}
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) == 0 {
			return answer, nil
		}
		entry.answer = answer
		entry.expires = received.Add(time.Duration(answer.Answer[0].Header().Ttl) * time.Second)
	}
	answer := entry.answer.Copy()
	ttl := uint32(max(0, entry.expires.Sub(e.now())/time.Second))
	for _, record := range answer.Answer {
		record.Header().Ttl = ttl
	}
	return answer, nil
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
	if source.IsLoopback() {
		return &policy{NetworkSpec: &runtimeconfig.NetworkSpec{Egress: "open"}}, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policies == nil {
		policies, err := e.loadPolicies()
		if err != nil {
			return nil, err
		}
		e.policies = policies
	}
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

func loadPolicies() ([]policy, error) {
	data, err := os.ReadFile(boot.RuntimeConfigPath)
	if err != nil {
		return nil, err
	}
	var config runtimeconfig.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	policies := make([]policy, 0, len(config.Networks))
	for name, network := range config.Networks {
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
				policies = append(policies, policy{name, prefix.Masked(), network})
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

func (e *Engine) authorizedAnswer(ctx context.Context, query, answer *dns.Msg, network string) (*dns.Msg, error) {
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
		if err := e.install(ctx, network, leases); err != nil {
			return nil, err
		}
		return reply, nil
	}
	return nil, fmt.Errorf("too many DNS aliases")
}

func (e *Engine) install(ctx context.Context, network string, leases map[string]uint32) error {
	if len(leases) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	set := containernet.AllowSetPrefix + network
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
