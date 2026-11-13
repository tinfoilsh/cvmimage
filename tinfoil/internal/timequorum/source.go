package timequorum

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"

	"tinfoil/internal/ntsrelay"
)

const (
	ConfiguredOperators = 5
	sourceAttemptLimit  = ntsrelay.ExchangeLimit / 2
)

type Source struct {
	Operator              Operator `json:"operator"`
	Servers               []string `json:"servers"`
	SPKISHA256            []string `json:"spki_sha256"`
	AssumeCompliant128GCM bool     `json:"assume_compliant_128gcm"`
}

type Sampler struct{ workers []*sourceWorker }

func NewSampler(sources []Source, relayBases []string) (*Sampler, error) {
	if len(sources) != ConfiguredOperators {
		return nil, fmt.Errorf("expected %d configured time operators", ConfiguredOperators)
	}
	if len(relayBases) == 0 {
		return nil, errors.New("no time relays configured")
	}
	var relays []*ntsrelay.Client
	for _, base := range relayBases {
		client, err := ntsrelay.NewClient(base)
		if err != nil {
			return nil, err
		}
		relays = append(relays, client)
	}
	sampler := &Sampler{}
	operators := map[Operator]bool{}
	owners := map[[sha256.Size]byte]Operator{}
	for _, source := range sources {
		if !source.Operator.valid() || operators[source.Operator] || len(source.Servers) == 0 || len(source.SPKISHA256) == 0 {
			return nil, errors.New("time operators must have unique identities, servers, and key pins")
		}
		operators[source.Operator] = true
		worker := &sourceWorker{source: source, relays: relays}
		worker.source.Servers = slices.Clone(source.Servers)
		for _, encoded := range source.SPKISHA256 {
			decoded, err := hex.DecodeString(encoded)
			if err != nil || len(decoded) != sha256.Size {
				return nil, fmt.Errorf("invalid key pin for %s", source.Operator)
			}
			var pin [sha256.Size]byte
			copy(pin[:], decoded)
			if owner, exists := owners[pin]; exists && owner != source.Operator {
				return nil, errors.New("time operators must not share an authentication key")
			}
			owners[pin] = source.Operator
			worker.pins = append(worker.pins, pin)
		}
		sampler.workers = append(sampler.workers, worker)
	}
	return sampler, nil
}

func (sampler *Sampler) Poll(parent context.Context) (Agreement, error) {
	ctx, cancel := context.WithTimeout(parent, ntsrelay.ExchangeLimit)
	defer cancel()
	type outcome struct {
		sample Sample
		err    error
	}
	results := make(chan outcome, len(sampler.workers))
	for _, worker := range sampler.workers {
		go func() { sample, err := worker.query(ctx); results <- outcome{sample, err} }()
	}
	var samples []Sample
	var failures []error
	for range sampler.workers {
		select {
		case result := <-results:
			if result.err != nil {
				failures = append(failures, result.err)
			} else {
				samples = append(samples, result.sample)
			}
		case <-ctx.Done():
			failures = append(failures, ctx.Err())
			return sampledAgreement(samples, failures)
		}
	}
	return sampledAgreement(samples, failures)
}

func sampledAgreement(samples []Sample, failures []error) (Agreement, error) {
	agreement, err := Agree(samples, time.Now())
	if err != nil {
		return Agreement{}, errors.Join(append([]error{err}, failures...)...)
	}
	return agreement, nil
}

type sourceWorker struct {
	mu      sync.Mutex
	source  Source
	pins    [][sha256.Size]byte
	relays  []*ntsrelay.Client
	session *nts.Session
	next    int
	// Refresh can occur after a cached session's original request has ended.
	// The library's dialer reads the context of the serialized current query.
	exchangeContext context.Context
}

func (worker *sourceWorker) query(parent context.Context) (Sample, error) {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	combinations := len(worker.relays) * len(worker.source.Servers)
	var failures []error
	for range combinations {
		if err := parent.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		ctx, cancel := context.WithTimeout(parent, sourceAttemptLimit)
		worker.exchangeContext = ctx
		relay := worker.relays[worker.next/len(worker.source.Servers)]
		address := worker.source.Servers[worker.next%len(worker.source.Servers)]
		sample, err := worker.attempt(ctx, relay, address)
		cancel()
		if err == nil {
			return sample, nil
		}
		worker.session = nil
		worker.next = (worker.next + 1) % combinations
		failures = append(failures, err)
	}
	return Sample{}, fmt.Errorf("%s: %w", worker.source.Operator, errors.Join(failures...))
}

func (worker *sourceWorker) attempt(ctx context.Context, relay *ntsrelay.Client, address string) (Sample, error) {
	if worker.session == nil {
		hostname := address
		if host, _, err := net.SplitHostPort(address); err == nil {
			hostname = host
		}
		session, err := nts.NewSessionWithOptions(address, &nts.SessionOptions{
			TLSConfig: worker.tlsConfig(hostname), Timeout: sourceAttemptLimit, AssumeCompliant128GCM: worker.source.AssumeCompliant128GCM,
			Dialer: func(network, address string, config *tls.Config) (*tls.Conn, error) {
				raw, err := relay.DialTCP(worker.exchangeContext, string(worker.source.Operator), address)
				if err != nil {
					return nil, err
				}
				connection := tls.Client(raw, config)
				if err := connection.HandshakeContext(worker.exchangeContext); err != nil {
					connection.Close()
					return nil, err
				}
				return connection, nil
			},
		})
		if err != nil {
			return Sample{}, err
		}
		worker.session = session
	}
	response, err := worker.session.QueryWithOptions(&ntp.QueryOptions{
		Timeout: sourceAttemptLimit, Version: 4, GetSystemTime: time.Now,
		Dialer: func(_, address string) (net.Conn, error) {
			return relay.DialUDP(ctx, string(worker.source.Operator), address)
		},
	})
	if err != nil {
		return Sample{}, err
	}
	if err := ctx.Err(); err != nil {
		return Sample{}, err
	}
	return Sample{Operator: worker.source.Operator, UTC: response.Timestamps.ServerXmit.Add(response.RTT / 2).UTC(),
		Received: response.Timestamps.ClientRecv, Radius: response.RootDistance}, nil
}

func (worker *sourceWorker) tlsConfig(hostname string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: hostname,
		// The measured image's public-key pins authenticate bootstrap
		// independently of certificate dates and public certificate issuers.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("time operator supplied no certificate")
			}
			leaf := state.PeerCertificates[0]
			if err := leaf.VerifyHostname(hostname); err != nil {
				return err
			}
			pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if !slices.Contains(worker.pins, pin) {
				return errors.New("time operator key does not match the measured pins")
			}
			return nil
		}}
}
