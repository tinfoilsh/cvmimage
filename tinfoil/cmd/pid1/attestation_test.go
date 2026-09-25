package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAttestationSocketSurvivesShimRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attestation.sock")
	file, err := newAttestationSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != attestationSocketMode {
		t.Fatalf("socket is not accessible to container users: %v, %v", info, err)
	}
	for _, name := range []string{"initial", "restarted"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.FileListener(file)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			served := make(chan error, 1)
			const response = "attestation"
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					served <- err
					return
				}
				defer conn.Close()
				_, err = io.WriteString(conn, response)
				served <- err
			}()
			conn, err := net.DialTimeout("unix", path, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(conn)
			if err != nil || string(body) != response {
				t.Fatalf("inherited listener response = %q, %v", body, err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		})
	}
}
