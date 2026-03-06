package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-acme/lego/v4/lego"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"

	"tinfoil/internal/config"
	"tinfoil/internal/dcode"
	"tinfoil/internal/key"
	"tinfoil/internal/key/online"
	tlsutil "tinfoil/internal/tls"
)

var version = "dev"

var (
	configFile         = flag.String("c", "/mnt/ramdisk/shim.yml", "Path to config file")
	externalConfigFile = flag.String("e", "/mnt/ramdisk/external-config.yml", "Path to external config file")
	dev                = flag.Bool("d", false, "Skip dcode domains, use dummy attestation, and enable verbose logging")
	httpMode           = flag.Bool("i", false, "Use HTTP instead of HTTPS (insecure)")
)

func main() {
	flag.Parse()

	config, externalConfig, err := config.Load(*configFile, *externalConfigFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if config.Verbose || *dev {
		log.SetLevel(log.DebugLevel)
	}

	log.Printf("Starting tinfoil attestation shim %s: %+v", version, config)

	var validator key.Validator
	var controlPlaneURL *url.URL

	if config.ControlPlane != "" {
		controlPlaneURL, err = url.Parse(config.ControlPlane)
		if err != nil {
			log.Fatalf("Failed to parse control plane URL: %v", err)
		}

		if config.Authenticated {
			validator, err = online.NewValidator(controlPlaneURL.JoinPath("api", "shim", "validate").String())
			if err != nil {
				log.Fatalf("Failed to initialize online API key verifier: %v", err)
			}
		} else {
			validator = nil
			log.Warn("API key verification disabled (unauthenticated endpoint)")
		}
	} else {
		validator = nil
		log.Warn("API key verification disabled (no control plane)")
	}

	// Generate or load HPKE key
	serverIdentity, err := identity.FromFile(config.HPKEKeyFile)
	if err != nil {
		logrus.Fatalf("Failed to get identity: %v", err)
	}

	// Generate key for TLS certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	if externalConfig.Domain == "" {
		externalConfig.Domain = "localhost"
	}

	hpkeKeyBytes := serverIdentity.MarshalPublicKey()
	if len(hpkeKeyBytes) != 32 {
		log.Fatalf("HPKE key length is not 32 bytes, got %d", len(hpkeKeyBytes))
	}
	var hpkeKey [32]byte
	copy(hpkeKey[:], hpkeKeyBytes)

	aBody := AttestationBodyV2{
		TLSKeyFP: tlsutil.KeyFPBytes(privateKey.Public().(*ecdsa.PublicKey)),
		HPKEKey:  hpkeKey,
	}
	log.WithFields(logrus.Fields{
		"tls_key_fp": fmt.Sprintf("%x", aBody.TLSKeyFP),
		"hpke_key":   fmt.Sprintf("%x", aBody.HPKEKey),
	}).Info("Attested keys")
	attestationBody := aBody.Marshal()

	// Request attestation
	log.Printf("Fetching attestation over %x", attestationBody)
	var att *attestation.Document
	if externalConfig.Domain == "localhost" || *dev || config.DummyAttestation {
		log.Warn("Using dummy attestation report")
		att = &attestation.Document{
			Format: "https://tinfoil.sh/predicate/dummy/v2",
			Body:   hex.EncodeToString(attestationBody[:]),
		}
	} else {
		att, err = attestationReport(attestationBody)
		if err != nil {
			log.Fatal(err)
		}
	}

	baseDomain := externalConfig.Domain

	// Domain used for encoded SANs (HPKE key, attestation).
	// Defaults to tinfoil.sh (control plane manages DNS); set own-encoded-domain
	// to use the base domain instead.
	encodedSANDomain := "tinfoil.sh"
	if config.TLSOwnSANDomain {
		encodedSANDomain = baseDomain
		if d, err := publicsuffix.EffectiveTLDPlusOne(baseDomain); err == nil {
			encodedSANDomain = d
		} else {
			log.Warnf("Failed to compute registrable domain for %q: %v; using as-is", baseDomain, err)
		}
	}
	log.Debugf("Encoded SAN domain: %s", encodedSANDomain)

	// Build encoded SANs (HPKE key + attestation)
	var encodedDomains []string
	hpkeKeyDomains, err := dcode.Encode(hpkeKeyBytes, "hpke."+encodedSANDomain)
	if err != nil {
		log.Fatalf("Failed to encode HPKE key: %v", err)
	}
	encodedDomains = append(encodedDomains, hpkeKeyDomains...)

	// Reserve SAN slots for non-encoded domains
	reservedSANs := 1 // base domain
	if config.TLSWildcard {
		reservedSANs = 2 // base + wildcard
	}

	if config.PublishAttestation {
		if config.PublishFullAttestation {
			log.Warn("Publishing full attestation document")
			attDomains, err := dcode.EncodeAtt(att, "att."+encodedSANDomain)
			if err != nil {
				log.Fatalf("Failed to encode attestation: %v", err)
			}
			if len(attDomains)+len(encodedDomains)+reservedSANs <= 100 {
				encodedDomains = append(encodedDomains, attDomains...)
			} else {
				log.Warn("Full attestation too large for certificate SANs, attestation not published")
			}
		} else {
			log.Warn("Publishing attestation document hash")
			attHashDomains, err := dcode.Encode([]byte(att.Hash()), "hatt."+encodedSANDomain)
			if err != nil {
				log.Fatalf("Failed to encode attestation hash: %v", err)
			}
			if len(attHashDomains)+len(encodedDomains)+reservedSANs <= 100 {
				encodedDomains = append(encodedDomains, attHashDomains...)
			} else {
				log.Fatalf("Attestation document hash is too large, cannot publish")
			}
		}
	}

	// Assemble domain list based on provider and challenge type
	var domains []string
	switch {
	case config.TLSMode == "cert-proxy" && config.TLSChallengeMode == "http":
		// Mixed relay: base domain (HTTP-01) + encoded SANs (DNS-01), no wildcard
		domains = append([]string{baseDomain}, encodedDomains...)
		log.Infof("cert-proxy+http: %d domains (base + %d encoded SANs)", len(domains), len(encodedDomains))
	case config.TLSMode != "cert-proxy" && (config.TLSChallengeMode == "tls" || config.TLSChallengeMode == "http"):
		// TLS-ALPN-01 or HTTP-01 only (non-cert-proxy): base domain only
		domains = []string{baseDomain}
		log.Warnf("%s challenge: only requesting certificate for base domain", config.TLSChallengeMode)
	default:
		// DNS-01, cert-proxy (pure DNS), self-signed
		if config.TLSWildcard {
			domains = append([]string{baseDomain, "*." + baseDomain}, encodedDomains...)
		} else {
			domains = append([]string{baseDomain}, encodedDomains...)
		}
	}

	for _, d := range domains {
		log.Debugf("Domain: %s", d)
	}

	// Obtain TLS certificate
	var cert *tls.Certificate
	if baseDomain == "localhost" || config.TLSMode == "self-signed" {
		cert, err = tlsutil.Certificate(privateKey, domains...)
		if err != nil {
			log.Fatalf("Failed to generate self signed TLS certificate: %v", err)
		}
	} else if config.TLSMode == "cert-proxy" {
		if config.ControlPlane == "" {
			log.Fatal("cert-proxy requires control-plane URL to be set")
		}
		// When tls-challenge is http, use mixed relay (HTTP-01 for base, DNS-01 for encoded SANs)
		var httpChallengeDomains []string
		var listenPort int
		if config.TLSChallengeMode == "http" {
			httpChallengeDomains = []string{baseDomain}
			listenPort = config.ListenPort
		}
		certProxyManager, err := tlsutil.NewCertProxyManager(
			domains,
			config.CacheDir,
			config.ControlPlane,
			privateKey,
			httpChallengeDomains,
			listenPort,
			externalConfig.CertAuthToken,
		)
		if err != nil {
			log.Fatalf("Failed to create cert proxy manager: %v", err)
		}

		duration := 5 * time.Minute
		for {
			cert, err = certProxyManager.Certificate()
			if err == nil {
				break
			}
			log.Warnf("Certificate request failed, will retry in %s: %v", duration.String(), err)
			time.Sleep(duration)
		}
	} else { // acme: direct ACME via Let's Encrypt
		dir := lego.LEDirectoryProduction
		if config.TLSEnv == "staging" {
			dir = lego.LEDirectoryStaging
		}
		certManager, err := tlsutil.NewCertManager(
			domains,
			config.Email, config.CacheDir, dir,
			tlsutil.ChallengeMode(config.TLSChallengeMode),
			config.ListenPort,
			privateKey,
			externalConfig.CloudflareDNSToken,
			externalConfig.CloudflareZoneToken,
		)
		if err != nil {
			log.Fatalf("Failed to create cert manager: %v", err)
		}

		duration := 18 * time.Minute
		for {
			cert, err = certManager.Certificate()
			if err == nil {
				break
			}
			log.Warnf("Certificate request failed, will retry in %s: %v", duration.String(), err)
			time.Sleep(duration)
		}
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}

	var rateLimiter *RateLimiter
	if config.RateLimit > 0 {
		rateLimiter = NewRateLimiter(rate.Limit(config.RateLimit), config.RateBurst)
	}

	listenAddr := fmt.Sprintf(":%d", config.ListenPort)
	httpServer := &http.Server{
		Addr:      listenAddr,
		Handler:   NewShimServer(validator, rateLimiter, att, serverIdentity, cert, config, externalConfig),
		TLSConfig: tlsConfig,
	}

	log.Printf("Listening on %s", listenAddr)
	if *httpMode {
		log.Warn("Running in HTTP mode (insecure)")
		log.Fatal(httpServer.ListenAndServe())
	} else {
		log.Fatal(httpServer.ListenAndServeTLS("", ""))
	}
}
