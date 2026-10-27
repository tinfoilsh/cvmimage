package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
)

// Run through image/test-sidecar.sh with the actual sidecar binary. Keeping the
// process boundary here avoids an application dependency in the runtime module.
func TestShimSidecarIntegration(t *testing.T) {
	binary := os.Getenv("TINFOIL_SIDECAR_BINARY")
	if binary == "" {
		t.Skip("set TINFOIL_SIDECAR_BINARY to exercise the real sidecar")
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, private2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	publicKeys := map[string]ed25519.PublicKey{"initial": pub}
	outage := false
	var validationHosts []string
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if outage {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/.well-known/jwks.json" {
			keys := []map[string]string{}
			for kid, pub := range publicKeys {
				keys = append(keys, map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(pub)})
			}
			json.NewEncoder(w).Encode(map[string]any{"keys": keys})
			return
		}
		if r.URL.Path != "/api/shim/validate-key" {
			w.WriteHeader(404)
			return
		}
		var request struct {
			APIKey string `json:"api_key"`
			Domain string `json:"domain"`
			Host   string `json:"requested_host"`
			Path   string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(400)
			return
		}
		validationHosts = append(validationHosts, request.Domain+"/"+request.Host)
		if request.Path == "/metrics" && request.APIKey != "admin" {
			w.WriteHeader(403)
			return
		}
		switch request.APIKey {
		case "valid", "admin":
			w.WriteHeader(200)
		case "forbidden":
			w.WriteHeader(403)
		case "payment":
			w.WriteHeader(402)
		case "limited":
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
		default:
			w.WriteHeader(401)
		}
	}))
	defer control.Close()
	directory := t.TempDir()
	ca := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: control.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	freePort := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	}
	port, upstreamPort := freePort(), freePort()
	policy, _ := json.Marshal(map[string]any{"version": 1, "authenticated": true, "control-plane": control.URL, "authenticated-endpoints": []string{"/v1/*", "/metrics"}, "paths": []string{"/v1/*", "/metrics", "/health"}, "origins": []string{"https://client.example"}})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--policy-version=1", executable, "-test.run=^TestShimSidecarUpstream$", "--")
	cmd.Env = append(os.Environ(), "SIDECAR_POLICY="+string(policy), "SIDECAR_LISTEN="+port, "SIDECAR_UPSTREAM_PORT="+upstreamPort, "SIDECAR_UPSTREAM_URL=", "DOMAIN=deployment.example", "SSL_CERT_FILE="+ca, "TINFOIL_UPSTREAM_FIXTURE=1", "TINFOIL_UPSTREAM_EXIT_PATH="+filepath.Join(directory, "child-exited"))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	direct := "http://127.0.0.1:" + port
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
		response, err := client.Get(direct + "/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("sidecar/upstream did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	shim := httptest.NewTLSServer(NewShimServer(tinfoilattestation.Identity{}, 0, id, nil, nil, &config.ExternalConfig{}, "127.0.0.1:"+port, nil))
	defer shim.Close()
	client = shim.Client()
	client.Timeout = 5 * time.Second
	send := func(target, path, token string, encrypted bool) (*http.Response, []byte) {
		t.Helper()
		request, _ := http.NewRequest(http.MethodPost, target+path, strings.NewReader(`{"stream":true}`))
		request.Host = "Model.Example:443"
		request.Header.Set("Origin", "https://client.example")
		request.Header.Set("X-Forwarded-Host", "forged.example")
		request.Header.Set("X-Tinfoil-Request-Usage-Metrics", "true")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		var encryption *identity.RequestContext
		if encrypted {
			encryption, err = id.EncryptRequestWithContext(request)
			if err != nil {
				t.Fatal(err)
			}
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if encrypted {
			if err := encryption.DecryptResponse(response); err != nil {
				t.Fatal(err)
			}
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response, body
	}
	for _, target := range []string{direct, shim.URL} {
		for _, tc := range []struct {
			token  string
			status int
		}{{"", 401}, {"bad", 401}, {"forbidden", 403}, {"payment", 402}, {"limited", 429}} {
			response, body := send(target, "/v1/chat/completions", tc.token, target == shim.URL)
			if response.StatusCode != tc.status || !json.Valid(body) {
				t.Fatalf("rejection %s: %d %s", tc.token, response.StatusCode, body)
			}
			if tc.status == 429 && response.Header.Get("Retry-After") != "7" {
				t.Fatal("lost Retry-After")
			}
			if response.Header.Get("Access-Control-Allow-Origin") != "https://client.example" {
				t.Fatal("lost workload CORS")
			}
		}
	}
	sign := func(kid string, private ed25519.PrivateKey) string {
		header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "at+jwt"})
		claims, _ := json.Marshal(map[string]any{"iss": control.URL, "aud": "https://inference.tinfoil.sh", "scope": "inference:api", "sub": "subject", "client_id": "client", "jti": "id", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
		message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
		return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))
	}
	initial := sign("initial", private)
	response, body := send(shim.URL, "/v1/chat/completions", initial, true)
	if response.StatusCode != 200 || !strings.Contains(string(body), "[DONE]") || response.Trailer.Get("X-Tinfoil-Usage-Metrics") == "" {
		t.Fatalf("stream/trailer lost: %d %s %v", response.StatusCode, body, response.Trailer)
	}
	if response, _ := send(shim.URL, "/metrics", initial, true); response.StatusCode != 403 {
		t.Fatal("inference JWT granted metrics access")
	}
	if response, body := send(direct, "/metrics", "admin", false); response.StatusCode != 200 || !strings.Contains(string(body), "requests_total") {
		t.Fatal("admin metrics unavailable")
	}
	mu.Lock()
	publicKeys["rotated"] = pub2
	mu.Unlock()
	rotated := sign("rotated", private2)
	if response, _ := send(shim.URL, "/v1/chat/completions", rotated, true); response.StatusCode != 200 {
		t.Fatal("JWKS rotation failed")
	}
	mu.Lock()
	outage = true
	mu.Unlock()
	if response, _ := send(shim.URL, "/v1/chat/completions", rotated, true); response.StatusCode != 200 {
		t.Fatal("cached key failed during outage")
	}
	if response, _ := send(shim.URL, "/v1/chat/completions", sign("unknown", private2), true); response.StatusCode != 401 {
		t.Fatal("unknown key accepted during outage")
	}
	if response, _ := send(shim.URL, "/v1/chat/completions", "valid", true); response.StatusCode != 503 {
		t.Fatal("online outage did not fail closed")
	}
	mu.Lock()
	for _, host := range validationHosts {
		if host != "deployment.example/model.example" {
			t.Errorf("forwarding/issuer request mismatch: %q", host)
		}
	}
	mu.Unlock()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if waitErr != nil {
			t.Fatal(waitErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sidecar did not stop")
	}
	if _, err := os.Stat(filepath.Join(directory, "child-exited")); err != nil {
		t.Fatal("sidecar did not signal/wait for its child")
	}
}

func TestShimSidecarUpstream(t *testing.T) {
	if os.Getenv("TINFOIL_UPSTREAM_FIXTURE") != "1" {
		return
	}
	port := os.Args[len(os.Args)-1]
	server := &http.Server{Addr: net.JoinHostPort("127.0.0.1", port), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			io.WriteString(w, "ready")
			return
		}
		if r.URL.Path == "/metrics" {
			io.WriteString(w, "requests_total 1\n")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\ndata: [DONE]\n\n")
	})}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	go func() { <-signals; server.Shutdown(context.Background()) }()
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("TINFOIL_UPSTREAM_EXIT_PATH"), []byte("stopped"), 0600); err != nil {
		t.Fatal(err)
	}
}
