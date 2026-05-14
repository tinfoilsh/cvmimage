package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/go-acme/lego/v4/lego"
	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"golang.org/x/net/publicsuffix"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/dcode"
	tlsutil "tinfoil/internal/tls"
)

const (
	secretCloudflareDNSToken  = "CLOUDFLARE_DNS_TOKEN"
	secretCloudflareZoneToken = "CLOUDFLARE_ZONE_TOKEN"
	secretCertAuthToken       = "CERT_AUTH_TOKEN"

	maxCertRetries     = 10
	maxCertificateSANs = 100

	certProxyRetryInterval = 5 * time.Minute
	acmeRetryInterval      = 18 * time.Minute
)

func obtainCertificate(id *NodeIdentity, att *verifier.Document, shimCfg *shimconfig.Config, externalConfig *shimconfig.ExternalConfig) error {
	encodedSANDomain := "tinfoil.sh"
	if shimCfg.TLSOwnSANDomain {
		encodedSANDomain = id.Domain
		if d, err := publicsuffix.EffectiveTLDPlusOne(id.Domain); err == nil {
			encodedSANDomain = d
		}
	}

	var encodedDomains []string
	hpkeKeyDomains, err := dcode.Encode(id.HPKEKeyBytes, "hpke."+encodedSANDomain)
	if err != nil {
		return fmt.Errorf("encoding HPKE key: %w", err)
	}
	encodedDomains = append(encodedDomains, hpkeKeyDomains...)

	reservedSANs := 1
	if shimCfg.TLSWildcard {
		reservedSANs = 2
	}

	if shimCfg.PublishAttestation {
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

	var domains []string
	switch {
	case shimCfg.TLSMode == "cert-proxy" && shimCfg.TLSChallengeMode == "http":
		domains = append([]string{id.Domain}, encodedDomains...)
	case shimCfg.TLSMode != "cert-proxy" && (shimCfg.TLSChallengeMode == "tls" || shimCfg.TLSChallengeMode == "http"):
		domains = []string{id.Domain}
	default:
		if shimCfg.TLSWildcard {
			domains = append([]string{id.Domain, "*." + id.Domain}, encodedDomains...)
		} else {
			domains = append([]string{id.Domain}, encodedDomains...)
		}
	}

	log.Printf("Obtaining TLS certificate for %d domains (mode=%s)", len(domains), shimCfg.TLSMode)

	cfDNS := externalConfig.GetSecret(secretCloudflareDNSToken)
	cfZone := externalConfig.GetSecret(secretCloudflareZoneToken)
	certAuthToken := externalConfig.GetSecret(secretCertAuthToken)

	var cert *tls.Certificate
	if id.Domain == "localhost" || shimCfg.TLSMode == "self-signed" {
		cert, err = tlsutil.Certificate(id.TLSKey, domains...)
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
			httpChallengeDomains = []string{id.Domain}
			listenPort = boot.HTTPChallengePort
			closeFW, err := openHTTP01Firewall(listenPort)
			if err != nil {
				return fmt.Errorf("opening HTTP-01 firewall: %w", err)
			}
			defer closeFW()
		}
		mgr, err := tlsutil.NewCertProxyManager(
			domains, boot.CacheDir, shimCfg.ControlPlane, id.TLSKey,
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
			domains, shimCfg.Email, boot.CacheDir, dir,
			tlsutil.ChallengeMode(shimCfg.TLSChallengeMode),
			boot.ShimListenPort, id.TLSKey,
			cfDNS, cfZone,
		)
		if err != nil {
			return fmt.Errorf("creating ACME cert manager: %w", err)
		}
		cert, err = retryCertificate(mgr.Certificate, acmeRetryInterval)
		if err != nil {
			return fmt.Errorf("obtaining cert via ACME: %w", err)
		}
	}

	return writeTLSArtifacts(cert, id.TLSKey)
}

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

func writeTLSArtifacts(cert *tls.Certificate, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(boot.TLSDir, 0700); err != nil {
		return fmt.Errorf("creating TLS directory: %w", err)
	}

	var certPEM []byte
	for _, derCert := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})...)
	}
	if err := os.WriteFile(boot.TLSCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing TLS cert: %w", err)
	}

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

var nftHandleRE = regexp.MustCompile(`# handle (\d+)`)

func openHTTP01Firewall(port int) (func(), error) {
	// nft delete rule wants a handle, not a match expression.
	args := []string{"--echo", "--handle", "add", "rule", "inet", "tinfoil", "input", "tcp", "dport", strconv.Itoa(port), "accept"}
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft %v: %w (%s)", args, err, out)
	}
	m := nftHandleRE.FindSubmatch(out)
	if m == nil {
		return nil, fmt.Errorf("nft add rule returned no handle: %s", out)
	}
	handle := string(m[1])
	return func() {
		del := []string{"delete", "rule", "inet", "tinfoil", "input", "handle", handle}
		if out, err := exec.Command("nft", del...).CombinedOutput(); err != nil {
			log.Printf("warning: nft delete HTTP-01 rule (handle %s) failed: %v (%s)", handle, err, out)
		}
	}, nil
}
