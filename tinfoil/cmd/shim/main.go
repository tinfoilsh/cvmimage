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
			if h, ok := handler.Load().(http.Handler); ok {
				h.ServeHTTP(w, r)
			} else {
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
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

// upgradeWhenReady polls for boot artifacts on the ramdisk, waits for all
// boot stages to complete, then builds the full shim handler and swaps it in.
// On failure the shim stays in boot-stages-only mode.
func upgradeWhenReady(handler *atomic.Value, cert *atomic.Pointer[tls.Certificate]) {
	start := time.Now()

	err := func() error {
		type configPair struct {
			config   *shimconfig.Config
			external *shimconfig.ExternalConfig
		}
		cfgPair, err := waitForArtifact("Shim config", func() (configPair, error) {
			c, e, err := shimconfig.Load(*configFile, *externalConfigFile)
			return configPair{c, e}, err
		})
		if err != nil {
			return err
		}
		config, externalConfig := cfgPair.config, cfgPair.external
		log.Printf("Shim config loaded: upstream-port=%d tls-mode=%s paths=%d", config.UpstreamPort, config.TLSMode, len(config.Paths))

		realCert, err := waitForArtifact("TLS certificate", func() (tls.Certificate, error) {
			return tls.LoadX509KeyPair(boot.TLSCertPath, boot.TLSKeyPath)
		})
		if err != nil {
			return err
		}
		cert.Store(&realCert)

		att, err := waitForArtifact("Attestation document", func() (*verifier.Document, error) {
			return loadAttestation()
		})
		if err != nil {
			return err
		}

		var attV3 json.RawMessage
		if data, err := os.ReadFile(boot.AttestationV3Path); err == nil {
			if json.Valid(data) {
				attV3 = data
			} else {
				log.Println("Warning: V3 attestation file is not valid JSON, ignoring")
			}
		}

		serverIdentity, err := waitForArtifact("HPKE identity", func() (*identity.Identity, error) {
			return identity.FromFile(config.HPKEKeyFile)
		})
		if err != nil {
			return err
		}

		// Wait for all boot stages (except shim) to resolve
		waitUntil(func() bool {
			state, err := boot.Load()
			if err != nil {
				return false
			}
			for _, s := range state.Stages {
				if s.Status == boot.StatusPending && s.Name != boot.StageShim {
					return false
				}
			}
			return true
		})

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

		fullHandler := NewShimServer(validator, rateLimiter, att, attV3, serverIdentity, cert.Load(), config, externalConfig)
		handler.Store(fullHandler)

		log.Println("Shim fully operational")
		return nil
	}()

	if err != nil {
		log.Printf("Shim upgrade failed: %v", err)
		boot.RecordStage(boot.StageShim, boot.StatusFailed, time.Since(start), err.Error())
	} else {
		boot.RecordStage(boot.StageShim, boot.StatusOK, time.Since(start), "")
	}
	boot.Complete()
}

// waitForArtifact polls load until it succeeds or boot fails.
func waitForArtifact[T any](name string, load func() (T, error)) (T, error) {
	for {
		state, _ := boot.Load()
		if state != nil && state.HasFailed() {
			var zero T
			return zero, fmt.Errorf("boot failed before %s was provisioned", name)
		}
		val, err := load()
		if err == nil {
			log.Printf("%s loaded", name)
			return val, nil
		}
		time.Sleep(artifactPollInterval)
	}
}

func waitUntil(cond func() bool) {
	for !cond() {
		time.Sleep(artifactPollInterval)
	}
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
