package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/creasty/defaults"
	"github.com/go-acme/lego/v4/lego"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"

	"tinfoil/internal/attestation"
	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/dcode"
	tlsutil "tinfoil/internal/tls"
)

const (
	maxCertRetries     = 10
	maxCertificateSANs = 100

	// cert-proxy relays through the control plane which responds quickly
	certProxyRetryInterval = 5 * time.Minute
	// ACME rate limits are stricter; Let's Encrypt allows 5 failures/hour
	acmeRetryInterval = 18 * time.Minute
)

func retryCertificate(fn func() (*tls.Certificate, error), interval time.Duration) (*tls.Certificate, error) {
	for attempt := range maxCertRetries {
		cert, err := fn()
		if err == nil {
			return cert, nil
		}
		log.Printf("Certificate request failed (attempt %d/%d), retrying in %s: %v", attempt+1, maxCertRetries, interval, err)
		time.Sleep(interval)
	}
	return nil, fmt.Errorf("certificate request failed after %d attempts", maxCertRetries)
}

// parseShimConfig converts the raw shim config map into the typed config struct.
func parseShimConfig(raw ShimConfig) (*shimconfig.Config, error) {
	var cfg shimconfig.Config
	if err := defaults.Set(&cfg); err != nil {
		return nil, fmt.Errorf("setting shim config defaults: %w", err)
	}
	yamlBytes, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshaling shim config: %w", err)
	}
	if err := yaml.Unmarshal(yamlBytes, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling shim config: %w", err)
	}
	return &cfg, nil
}

// initCrypto generates keys, fetches attestation, and obtains a TLS certificate.
// This runs before containers start so the attestation-bound cert exists first.
func initCrypto(bootConfig *Config, externalConfig *ExternalConfig) error {
	shimCfg, err := parseShimConfig(bootConfig.Shim)
	if err != nil {
		return fmt.Errorf("parsing shim config: %w", err)
	}

	domain := ""
	if externalConfig.Env != nil {
		domain = externalConfig.Env["DOMAIN"]
	}
	if domain == "" {
		domain = "localhost"
	}

	hpkeKeyFile := shimCfg.HPKEKeyFile
	if hpkeKeyFile == "" {
		hpkeKeyFile = boot.HPKEKeyPath
	}
	serverIdentity, err := identity.FromFile(hpkeKeyFile)
	if err != nil {
		return fmt.Errorf("loading HPKE identity: %w", err)
	}

	hpkeKeyBytes := serverIdentity.MarshalPublicKey()
	if len(hpkeKeyBytes) != 32 {
		return fmt.Errorf("HPKE key length is %d, expected 32", len(hpkeKeyBytes))
	}
	var hpkeKey [32]byte
	copy(hpkeKey[:], hpkeKeyBytes)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating TLS key: %w", err)
	}

	aBody := attestation.BodyV2{
		TLSKeyFP: tlsutil.KeyFPBytes(privateKey.Public().(*ecdsa.PublicKey)),
		HPKEKey:  hpkeKey,
	}
	log.Printf("Attestation body: tls_fp=%x hpke=%x", aBody.TLSKeyFP, aBody.HPKEKey)
	attestationBody := aBody.Marshal()

	var att *verifier.Document
	if domain == "localhost" || shimCfg.DummyAttestation {
		log.Println("Using dummy attestation report")
		att = attestation.DummyReport(attestationBody)
	} else {
		log.Println("Fetching hardware attestation report")
		att, err = attestation.Report(attestationBody)
		if err != nil {
			return fmt.Errorf("fetching attestation report: %w", err)
		}
	}

	encodedSANDomain := "tinfoil.sh"
	if shimCfg.TLSOwnSANDomain {
		encodedSANDomain = domain
		if d, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
			encodedSANDomain = d
		}
	}

	var encodedDomains []string
	hpkeKeyDomains, err := dcode.Encode(hpkeKeyBytes, "hpke."+encodedSANDomain)
	if err != nil {
		return fmt.Errorf("encoding HPKE key: %w", err)
	}
	encodedDomains = append(encodedDomains, hpkeKeyDomains...)

	reservedSANs := 1
	if shimCfg.TLSWildcard {
		reservedSANs = 2
	}

	if shimCfg.PublishAttestation {
		if shimCfg.PublishFullAttestation {
			attDomains, err := dcode.EncodeAtt(att, "att."+encodedSANDomain)
			if err != nil {
				return fmt.Errorf("encoding attestation: %w", err)
			}
			if len(attDomains)+len(encodedDomains)+reservedSANs <= maxCertificateSANs {
				encodedDomains = append(encodedDomains, attDomains...)
			} else {
				log.Println("WARNING: full attestation too large for certificate SANs")
			}
		} else {
			attHashDomains, err := dcode.Encode([]byte(att.Hash()), "hatt."+encodedSANDomain)
			if err != nil {
				return fmt.Errorf("encoding attestation hash: %w", err)
			}
			if len(attHashDomains)+len(encodedDomains)+reservedSANs <= maxCertificateSANs {
				encodedDomains = append(encodedDomains, attHashDomains...)
			} else {
				return fmt.Errorf("attestation hash too large for certificate SANs")
			}
		}
	}

	var domains []string
	switch {
	case shimCfg.TLSMode == "cert-proxy" && shimCfg.TLSChallengeMode == "http":
		domains = append([]string{domain}, encodedDomains...)
	case shimCfg.TLSMode != "cert-proxy" && (shimCfg.TLSChallengeMode == "tls" || shimCfg.TLSChallengeMode == "http"):
		domains = []string{domain}
	default:
		if shimCfg.TLSWildcard {
			domains = append([]string{domain, "*." + domain}, encodedDomains...)
		} else {
			domains = append([]string{domain}, encodedDomains...)
		}
	}

	log.Printf("Obtaining TLS certificate for %d domains (mode=%s)", len(domains), shimCfg.TLSMode)

	cloudflareTokens := getCloudflareTokens(externalConfig)
	certAuthToken := getCertAuthToken(externalConfig)

	var cert *tls.Certificate
	if domain == "localhost" || shimCfg.TLSMode == "self-signed" {
		cert, err = tlsutil.Certificate(privateKey, domains...)
		if err != nil {
			return fmt.Errorf("generating self-signed cert: %w", err)
		}
	} else if shimCfg.TLSMode == "cert-proxy" {
		if shimCfg.ControlPlane == "" {
			return fmt.Errorf("cert-proxy requires control-plane URL")
		}
		var httpChallengeDomains []string
		var listenPort int
		if shimCfg.TLSChallengeMode == "http" {
			httpChallengeDomains = []string{domain}
			listenPort = shimCfg.ListenPort
		}
		mgr, err := tlsutil.NewCertProxyManager(
			domains, shimCfg.CacheDir, shimCfg.ControlPlane, privateKey,
			httpChallengeDomains, listenPort, certAuthToken,
		)
		if err != nil {
			return fmt.Errorf("creating cert proxy manager: %w", err)
		}
		cert, err = retryCertificate(mgr.Certificate, certProxyRetryInterval)
		if err != nil {
			return fmt.Errorf("obtaining cert via cert-proxy: %w", err)
		}
	} else {
		dir := lego.LEDirectoryProduction
		if shimCfg.TLSEnv == "staging" {
			dir = lego.LEDirectoryStaging
		}
		mgr, err := tlsutil.NewCertManager(
			domains, shimCfg.Email, shimCfg.CacheDir, dir,
			tlsutil.ChallengeMode(shimCfg.TLSChallengeMode),
			shimCfg.ListenPort, privateKey,
			cloudflareTokens[0], cloudflareTokens[1],
		)
		if err != nil {
			return fmt.Errorf("creating ACME cert manager: %w", err)
		}
		cert, err = retryCertificate(mgr.Certificate, acmeRetryInterval)
		if err != nil {
			return fmt.Errorf("obtaining cert via ACME: %w", err)
		}
	}

	if err := writeTLSArtifacts(cert, privateKey); err != nil {
		return err
	}
	if err := writeAttestationDoc(att); err != nil {
		return err
	}

	return nil
}

func getCloudflareTokens(ext *ExternalConfig) [2]string {
	if ext.Secrets == nil {
		return [2]string{}
	}
	return [2]string{ext.Secrets["cloudflare-dns-token"], ext.Secrets["cloudflare-zone-token"]}
}

func getCertAuthToken(ext *ExternalConfig) string {
	if ext.Secrets == nil {
		return ""
	}
	return ext.Secrets["CERT_AUTH_TOKEN"]
}

func writeTLSArtifacts(cert *tls.Certificate, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(boot.TLSDir, 0700); err != nil {
		return fmt.Errorf("creating TLS directory: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(boot.TLSCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing TLS cert: %w", err)
	}

	// Write private key PEM
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling TLS key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(boot.TLSKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing TLS key: %w", err)
	}

	log.Println("TLS certificate and key written to ramdisk")
	return nil
}

func writeAttestationDoc(att *verifier.Document) error {
	data, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling attestation document: %w", err)
	}
	if err := os.WriteFile(boot.AttestationPath, data, 0644); err != nil {
		return fmt.Errorf("writing attestation document: %w", err)
	}
	log.Println("Attestation document written to ramdisk")
	return nil
}
