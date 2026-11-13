// Package ntsrelay transports upstream NTS traffic without authenticating time.
// Callers must authenticate upstream TLS and NTP responses independently.
package ntsrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	ExchangeLimit = 8 * time.Second
	PacketLimit   = 2048
	peerHeader    = "X-Time-Relay-Peer"
)

type Client struct {
	base url.URL
	http *http.Client
}

func NewClient(base string) (*Client, error) {
	client := &Client{http: &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			// The initial date is untrusted. Authentication belongs to the
			// inner upstream TLS connection; the relay can only deny service.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid time relay: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("time relay must be an HTTPS base URL")
	}
	client.base = *parsed
	return client, nil
}

func (client *Client) DialTCP(ctx context.Context, operator, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, ExchangeLimit)
	socket, peer, err := client.dial(ctx, operator, "tcp", address)
	if err != nil {
		cancel()
		return nil, err
	}
	connection := websocket.NetConn(ctx, socket, websocket.MessageBinary)
	return &relayConnection{Conn: connection, peer: peer, cancel: cancel, socket: socket}, nil
}

func (client *Client) DialUDP(ctx context.Context, operator, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, ExchangeLimit)
	socket, peer, err := client.dial(ctx, operator, "udp", address)
	if err != nil {
		cancel()
		return nil, err
	}
	socket.SetReadLimit(PacketLimit)
	local, worker := net.Pipe()
	stop := context.AfterFunc(ctx, func() { worker.Close(); socket.CloseNow() })
	go func() {
		defer worker.Close()
		defer socket.CloseNow()
		defer stop()
		packet := make([]byte, PacketLimit+1)
		n, err := worker.Read(packet)
		if err != nil || n > PacketLimit {
			return
		}
		if err := socket.Write(ctx, websocket.MessageBinary, packet[:n]); err != nil {
			return
		}
		kind, response, err := socket.Read(ctx)
		if err != nil || kind != websocket.MessageBinary {
			return
		}
		// One pipe write keeps the entire datagram available to the NTP read,
		// even if its WebSocket message arrives in multiple network reads.
		worker.Write(response)
	}()
	return &relayConnection{Conn: local, peer: peer, cancel: cancel, socket: socket}, nil
}

func (client *Client) dial(ctx context.Context, operator, network, address string) (*websocket.Conn, net.Addr, error) {
	if operator == "" || operator == "." || operator == ".." || url.PathEscape(operator) != operator {
		return nil, nil, errors.New("invalid time operator")
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, nil, fmt.Errorf("invalid upstream address: %w", err)
	}
	target := client.base
	target.Path = strings.TrimRight(target.Path, "/") + "/time-relay/" + operator
	target.RawPath = ""
	target.RawQuery = url.Values{"network": {network}, "address": {address}}.Encode()
	socket, response, err := websocket.Dial(ctx, target.String(), &websocket.DialOptions{HTTPClient: client.http})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return nil, nil, err
	}
	peer, err := netip.ParseAddrPort(response.Header.Get(peerHeader))
	if err != nil {
		socket.CloseNow()
		return nil, nil, fmt.Errorf("invalid relay peer address: %w", err)
	}
	return socket, relayAddress{network: network, peer: peer}, nil
}

type relayAddress struct {
	network string
	peer    netip.AddrPort
}

func (address relayAddress) Network() string { return address.network }
func (address relayAddress) String() string  { return address.peer.String() }

type relayConnection struct {
	net.Conn
	peer   net.Addr
	cancel context.CancelFunc
	socket *websocket.Conn
	once   sync.Once
}

func (connection *relayConnection) RemoteAddr() net.Addr { return connection.peer }
func (connection *relayConnection) Close() error {
	var err error
	// Abortive teardown avoids a peer-controlled WebSocket close-handshake wait.
	connection.once.Do(func() { connection.cancel(); connection.socket.CloseNow(); err = connection.Conn.Close() })
	return err
}
