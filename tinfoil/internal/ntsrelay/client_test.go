package ntsrelay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const testLimit = 5 * time.Second

func testRelay(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type fragmentedConnection struct{ net.Conn }

func (connection fragmentedConnection) Write(data []byte) (int, error) {
	const fragmentSize = 7
	total := 0
	for len(data) > 0 {
		n, err := connection.Conn.Write(data[:min(fragmentSize, len(data))])
		total += n
		data = data[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

type fragmentedWriter struct{ http.ResponseWriter }

func (writer fragmentedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	connection, buffered, err := http.NewResponseController(writer.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	if err := buffered.Flush(); err != nil {
		connection.Close()
		return nil, nil, err
	}
	fragmented := fragmentedConnection{connection}
	return fragmented, bufio.NewReadWriter(buffered.Reader, bufio.NewWriter(fragmented)), nil
}

func TestUDPReadPreservesFragmentedDatagram(t *testing.T) {
	payload := bytes.Repeat([]byte("authenticated datagram"), 64)
	query := bytes.Repeat([]byte{0xa5}, 48)
	client := testRelay(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/time-relay/canonical" || r.URL.Query().Get("address") != "upstream.invalid:123" || r.URL.Query().Get("network") != "udp" {
			t.Error("upstream routing changed")
			return
		}
		w.Header().Set(peerHeader, "192.0.2.1:123")
		socket, err := websocket.Accept(fragmentedWriter{w}, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer socket.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), testLimit)
		defer cancel()
		kind, got, err := socket.Read(ctx)
		if err != nil || kind != websocket.MessageBinary || !bytes.Equal(got, query) {
			t.Errorf("query=%x error=%v", got, err)
			return
		}
		if err := socket.Write(ctx, websocket.MessageBinary, payload); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), testLimit)
	defer cancel()
	connection, err := client.DialUDP(ctx, "canonical", "upstream.invalid:123")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.RemoteAddr().String() != "192.0.2.1:123" {
		t.Fatal("relay peer metadata was lost")
	}
	if _, err := connection.Write(query); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, PacketLimit)
	n, err := connection.Read(response)
	if err != nil || !bytes.Equal(response[:n], payload) {
		t.Fatalf("datagram length=%d, want %d; error=%v", n, len(payload), err)
	}
}

func TestTCPPreservesStreamAndPeer(t *testing.T) {
	payload := []byte("opaque upstream handshake")
	client := testRelay(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(peerHeader, "[2001:db8::1]:4460")
		socket, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer socket.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), testLimit)
		defer cancel()
		connection := websocket.NetConn(ctx, socket, websocket.MessageBinary)
		data := make([]byte, len(payload))
		if _, err := io.ReadFull(connection, data); err != nil {
			t.Error(err)
			return
		}
		if _, err := connection.Write(data); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), testLimit)
	defer cancel()
	connection, err := client.DialTCP(ctx, "canonical", "upstream.invalid:4460")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.RemoteAddr().String() != "[2001:db8::1]:4460" {
		t.Fatal("upstream address changed")
	}
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("relay changed stream bytes")
	}
}

func TestUDPCancellationAndDeadlines(t *testing.T) {
	client := testRelay(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(peerHeader, "192.0.2.1:123")
		socket, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer socket.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), testLimit)
		defer cancel()
		for {
			if _, _, err := socket.Read(ctx); err != nil {
				return
			}
		}
	})
	for _, cancelParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "read deadline", true: "parent canceled"}[cancelParent], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testLimit)
			defer cancel()
			connection, err := client.DialUDP(ctx, "canonical", "upstream.invalid:123")
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if cancelParent {
				cancel()
			} else {
				if _, err := connection.Write([]byte("request")); err != nil {
					t.Fatal(err)
				}
				if err := connection.SetReadDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			_, err = connection.Read(make([]byte, PacketLimit))
			if err == nil {
				t.Fatal("read succeeded without an upstream response")
			}
			if !cancelParent {
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("read error is not a timeout: %v", err)
				}
			}
		})
	}
}

func TestRejectsMalformedPeerAndRedirects(t *testing.T) {
	for _, peer := range []string{"", "upstream.invalid:123", "not an address"} {
		t.Run(peer, func(t *testing.T) {
			client := testRelay(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(peerHeader, peer)
				socket, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer socket.CloseNow()
				ctx, cancel := context.WithTimeout(context.Background(), testLimit)
				defer cancel()
				socket.Read(ctx)
			})
			ctx, cancel := context.WithTimeout(context.Background(), testLimit)
			defer cancel()
			if connection, err := client.DialTCP(ctx, "canonical", "upstream.invalid:4460"); err == nil {
				connection.Close()
				t.Fatal("malformed relay peer accepted")
			}
		})
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("followed a relay redirect") }))
	defer target.Close()
	client := testRelay(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	ctx, cancel := context.WithTimeout(context.Background(), testLimit)
	defer cancel()
	if connection, err := client.DialTCP(ctx, "canonical", "upstream.invalid:4460"); err == nil {
		connection.Close()
		t.Fatal("relay redirect accepted")
	}
}

func TestRelayFailureNeverDialsUpstream(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("direct upstream request") }))
	defer upstream.Close()
	relay := httptest.NewTLSServer(http.NotFoundHandler())
	base := relay.URL
	relay.Close()
	client, err := NewClient(base)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testLimit)
	defer cancel()
	if connection, err := client.DialTCP(ctx, "canonical", upstream.Listener.Addr().String()); err == nil {
		connection.Close()
		t.Fatal("unavailable relay did not fail closed")
	}
}
