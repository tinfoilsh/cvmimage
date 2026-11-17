package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

type countingListener struct {
	net.Listener
	mu          sync.Mutex
	connections []net.Conn
}

func (l *countingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.connections = append(l.connections, connection)
		l.mu.Unlock()
	}
	return connection, err
}

func (l *countingListener) accepted() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.connections)
}

func (l *countingListener) closeConnections() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, connection := range l.connections {
		connection.Close()
	}
}

func trustedResolver(t *testing.T) (*countingListener, *tls.Config) {
	t.Helper()
	certificateServer := httptest.NewTLSServer(nil)
	serverConfig := certificateServer.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())
	certificateServer.Close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countingListener{Listener: tcp}
	ready := make(chan struct{})
	server := &dns.Server{
		Listener:          tls.NewListener(listener, serverConfig),
		NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			_ = w.WriteMsg(new(dns.Msg).SetReply(q))
		}),
	}
	go server.ActivateAndServe()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	return listener, &tls.Config{RootCAs: roots, ServerName: "example.com"}
}

func TestUpstreamReusesConnectionsAndReplacesClosedOnes(t *testing.T) {
	listener, config := trustedResolver(t)
	resolver := newUpstream([]string{listener.Addr().String()}, config)
	query := func() {
		t.Helper()
		if _, err := resolver.exchange(context.Background(), new(dns.Msg).SetQuestion("storage.example.", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		query()
	}
	if listener.accepted() != 1 {
		t.Fatalf("lookups opened %d connections", listener.accepted())
	}
	listener.closeConnections()
	query()
	if listener.accepted() != 2 {
		t.Fatalf("lookup after a closed connection opened %d connections in total", listener.accepted())
	}
}

func TestUpstreamStartsWithTheAddressThatAnsweredLast(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failing := &countingListener{Listener: tcp}
	t.Cleanup(func() { failing.Close() })
	go func() {
		for {
			connection, err := failing.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	listener, config := trustedResolver(t)
	resolver := newUpstream([]string{failing.Addr().String(), listener.Addr().String()}, config)
	for range 3 {
		if _, err := resolver.exchange(context.Background(), new(dns.Msg).SetQuestion("storage.example.", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	if failing.accepted() != 1 {
		t.Fatalf("failing address was tried %d times", failing.accepted())
	}
}
