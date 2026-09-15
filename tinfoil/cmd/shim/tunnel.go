package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"tinfoil/internal/containernet"
	"tinfoil/internal/runtimeconfig"
)

const (
	tunnelDialTimeout = 5 * time.Second
	tunnelIdleTimeout = 5 * time.Minute
	maxOpenTunnels    = 128
)

func publishedPorts(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var runtime runtimeconfig.Config
	if err := yaml.Unmarshal(data, &runtime); err != nil {
		return nil, err
	}
	targets := map[string]bool{}
	for _, container := range runtime.Containers {
		mappings, err := runtimeconfig.ParsePorts(container.Ports)
		if err != nil {
			return nil, fmt.Errorf("container %s: %v", container.Name, err)
		}
		for _, mapping := range mappings {
			port := strconv.Itoa(mapping.Host)
			targets[port] = true
			log.Printf("Tunnel: CONNECT :%s → %s:%s (%s)", port, containernet.PublishedHostIP, port, container.Name)
		}
	}
	return targets, nil
}

func tunnels(targets map[string]bool, authorize func(http.ResponseWriter, *http.Request) bool, next http.Handler) http.Handler {
	var open atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			next.ServeHTTP(w, r)
			return
		}
		if r.ProtoMajor != 2 {
			http.Error(w, "tunnels require HTTP/2", http.StatusMethodNotAllowed)
			return
		}
		// Authorizing before the target lookup keeps the published set from
		// leaking: an unkeyed CONNECT gets 401 whether or not a port exists.
		if !authorize(w, r) {
			return
		}
		_, port, _ := net.SplitHostPort(r.Host)
		if !targets[port] {
			http.Error(w, "no container publishes this port", http.StatusNotFound)
			return
		}
		if open.Add(1) > maxOpenTunnels {
			open.Add(-1)
			http.Error(w, "too many open tunnels", http.StatusServiceUnavailable)
			return
		}
		defer open.Add(-1)

		address := net.JoinHostPort(containernet.PublishedHostIP, port)
		dialed, err := net.DialTimeout("tcp", address, tunnelDialTimeout)
		if err != nil {
			log.Printf("Tunnel: dialing %s failed: %v", address, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		conn := dialed.(*net.TCPConn)
		defer conn.Close()

		control := http.NewResponseController(w)
		w.WriteHeader(http.StatusOK)
		if err := control.Flush(); err != nil {
			return
		}

		go func() {
			_, _ = io.Copy(idleConn{conn}, r.Body)
			// A client half-close must not drop replies still in flight.
			_ = conn.CloseWrite()
		}()
		_, _ = io.Copy(flushWriter{w, control}, idleConn{conn})
	})
}

// idleConn bounds tunnel idle time; embedding would let io.Copy's ReadFrom skip the deadline.
type idleConn struct {
	conn *net.TCPConn
}

func (c idleConn) Read(p []byte) (int, error) {
	_ = c.conn.SetDeadline(time.Now().Add(tunnelIdleTimeout))
	return c.conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	_ = c.conn.SetDeadline(time.Now().Add(tunnelIdleTimeout))
	return c.conn.Write(p)
}

// flushWriter pushes each read out as its own frame; h2 would buffer instead.
type flushWriter struct {
	writer  io.Writer
	control *http.ResponseController
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.writer.Write(p)
	if err == nil {
		err = f.control.Flush()
	}
	return n, err
}
