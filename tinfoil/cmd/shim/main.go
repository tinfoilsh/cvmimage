package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"log"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"golang.org/x/time/rate"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/key"
	"tinfoil/internal/key/online"
)

var version = "dev"

var (
	configFile         = flag.String("c", boot.ShimConfigPath, "Path to config file")
	externalConfigFile = flag.String("e", boot.ExternalConfigPath, "Path to external config file")
)

func main() {
	flag.Parse()
	log.SetFlags(0)

	var handler atomic.Value
	var cert atomic.Pointer[tls.Certificate]

	// Start with an ephemeral self-signed cert and a minimal handler that
	// serves only boot-stages. This lets the backend poll boot progress before
	// boot has provisioned the real TLS cert and other artifacts.
	ephemeral, err := generateEphemeralCert()
	if err != nil {
		log.Fatalf("Failed to generate ephemeral cert: %v", err)
	}
	cert.Store(&ephemeral)

	handler.Store(bootStagesHandler())

	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert.Load(), nil
		},
	}

	srv := &http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.Load().(http.Handler).ServeHTTP(w, r)
		}),
		TLSConfig: tlsConfig,
	}

	// Wait for boot to provision artifacts, then upgrade to the full handler.
	go upgradeWhenReady(&handler, &cert)

	log.Printf("Starting tinfoil shim %s (waiting for boot)", version)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// bootStagesHandler returns a minimal handler that only serves the
// boot-stages endpoint, returning 503 for everything else.
func bootStagesHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/tinfoil-boot-stages", func(w http.ResponseWriter, r *http.Request) {
		state, err := boot.Load()
		if err != nil {
			http.Error(w, "boot state not available", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "shim is starting, waiting for boot to complete", http.StatusServiceUnavailable)
	})
	return mux
}

const artifactPollInterval = 1 * time.Second

// upgradeWhenReady polls for boot artifacts on the ramdisk. Once everything
// is available, it builds the full shim handler and swaps it in. If boot
// fails or an artifact can't be loaded, the failure is recorded as a "shim"
// stage and the shim stays in boot-stages-only mode.
func upgradeWhenReady(handler *atomic.Value, cert *atomic.Pointer[tls.Certificate]) {
	start := time.Now()

	if err := doUpgrade(handler, cert); err != nil {
		log.Printf("Shim upgrade failed: %v", err)
		boot.AppendStage("shim", boot.StatusFailed, time.Since(start), err.Error())
		return
	}

	boot.AppendStage("shim", boot.StatusOK, time.Since(start), "")
}

func doUpgrade(handler *atomic.Value, cert *atomic.Pointer[tls.Certificate]) error {
	// Wait for config files (or boot failure)
	var config *shimconfig.Config
	var externalConfig *shimconfig.ExternalConfig
	for {
		if bootFailed() {
			return fmt.Errorf("boot failed")
		}
		var err error
		config, externalConfig, err = shimconfig.Load(*configFile, *externalConfigFile)
		if err == nil {
			break
		}
		time.Sleep(artifactPollInterval)
	}
	log.Printf("Shim config loaded: %+v", config)

	// Wait for TLS certificate (or boot failure)
	for {
		if bootFailed() {
			return fmt.Errorf("boot failed before TLS certificate was provisioned")
		}
		realCert, err := tls.LoadX509KeyPair(boot.TLSCertPath, boot.TLSKeyPath)
		if err == nil {
			cert.Store(&realCert)
			log.Println("TLS certificate loaded")
			break
		}
		time.Sleep(artifactPollInterval)
	}

	// Wait for attestation document (or boot failure)
	var att *verifier.Document
	for {
		if bootFailed() {
			return fmt.Errorf("boot failed before attestation was provisioned")
		}
		var err error
		att, err = loadAttestation()
		if err == nil {
			break
		}
		time.Sleep(artifactPollInterval)
	}
	log.Println("Attestation document loaded")

	var attV3 json.RawMessage
	if data, err := os.ReadFile(boot.AttestationV3Path); err == nil {
		if json.Valid(data) {
			attV3 = data
		} else {
			log.Println("Warning: V3 attestation file is not valid JSON, ignoring")
		}
	}

	// Wait for HPKE identity (or boot failure)
	var serverIdentity *identity.Identity
	for {
		if bootFailed() {
			return fmt.Errorf("boot failed before HPKE identity was provisioned")
		}
		var err error
		serverIdentity, err = identity.FromFile(config.HPKEKeyFile)
		if err == nil {
			break
		}
		time.Sleep(artifactPollInterval)
	}
	log.Println("HPKE identity loaded")

	// API key validator
	var validator key.Validator
	if config.ControlPlane != "" {
		controlPlaneURL, err := url.Parse(config.ControlPlane)
		if err != nil {
			return fmt.Errorf("parsing control plane URL: %w", err)
		}

		if config.Authenticated {
			validator, err = online.NewValidator(controlPlaneURL.JoinPath("api", "shim", "validate").String())
			if err != nil {
				return fmt.Errorf("initializing API key verifier: %w", err)
			}
		} else {
			log.Println("Warning: API key verification disabled (unauthenticated endpoint)")
		}
	} else {
		log.Println("Warning: API key verification disabled (no control plane)")
	}

	var rateLimiter *RateLimiter
	if config.RateLimit > 0 {
		rateLimiter = NewRateLimiter(rate.Limit(config.RateLimit), config.RateBurst)
	}

	realCert := cert.Load()
	fullHandler := NewShimServer(validator, rateLimiter, att, attV3, serverIdentity, realCert, config, externalConfig)
	handler.Store(fullHandler)

	log.Printf("Shim fully operational on :%d", config.ListenPort)
	return nil
}

// bootFailed checks if the boot process has recorded a failed stage.
func bootFailed() bool {
	state, err := boot.Load()
	if err != nil {
		return false
	}
	return state.HasFailed()
}

func generateEphemeralCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

func loadAttestation() (*verifier.Document, error) {
	data, err := os.ReadFile(boot.AttestationPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", boot.AttestationPath, err)
	}
	var att verifier.Document
	if err := json.Unmarshal(data, &att); err != nil {
		return nil, fmt.Errorf("parsing attestation document: %w", err)
	}
	return &att, nil
}
