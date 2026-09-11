package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/go-acme/lego/v4/lego"
	"golang.org/x/net/publicsuffix"

	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/dcode"
	"tinfoil/internal/firewall"
	"tinfoil/internal/secretstore"
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

// Request contains the node material endorsed by the certificate.
type Request struct {
	Domain          string
	Key             *ecdsa.PrivateKey
	HPKEKey         []byte
	AttestationHash string
}

func Provision(ctx context.Context, request Request, shimCfg *shimconfig.Config, credentials secretstore.Store) (*tls.Certificate, error) {
	encodedSANDomain := "tinfoil.sh"
	if shimCfg.TLSOwnSANDomain {
		encodedSANDomain = request.Domain
		if d, err := publicsuffix.EffectiveTLDPlusOne(request.Domain); err == nil {
			encodedSANDomain = d
		}
	}

	var encodedDomains []string
	hpkeKeyDomains, err := dcode.Encode(request.HPKEKey, "hpke."+encodedSANDomain)
	if err != nil {
		return nil, fmt.Errorf("encoding HPKE key: %w", err)
	}
	encodedDomains = append(encodedDomains, hpkeKeyDomains...)

	reservedSANs := 1
	if shimCfg.TLSWildcard {
		reservedSANs = 2
	}

	if shimCfg.PublishAttestation {
		attHashDomains, err := dcode.Encode([]byte(request.AttestationHash), "hatt."+encodedSANDomain)
		if err != nil {
			return nil, fmt.Errorf("encoding attestation hash: %w", err)
		}
		if len(attHashDomains)+len(encodedDomains)+reservedSANs <= maxCertificateSANs {
			encodedDomains = append(encodedDomains, attHashDomains...)
		} else {
			return nil, fmt.Errorf("attestation hash too large for certificate SANs")
		}
	}

	var domains []string
	switch {
	case shimCfg.TLSMode == "cert-proxy" && shimCfg.TLSChallengeMode == "http":
		domains = append([]string{request.Domain}, encodedDomains...)
	case shimCfg.TLSMode != "cert-proxy" && (shimCfg.TLSChallengeMode == "tls" || shimCfg.TLSChallengeMode == "http"):
		domains = []string{request.Domain}
	default:
		if shimCfg.TLSWildcard {
			domains = append([]string{request.Domain, "*." + request.Domain}, encodedDomains...)
		} else {
			domains = append([]string{request.Domain}, encodedDomains...)
		}
	}

	log.Printf("Obtaining TLS certificate for %d domains (mode=%s)", len(domains), shimCfg.TLSMode)

	cfDNS := credentials.GetSecret(secretCloudflareDNSToken)
	cfZone := credentials.GetSecret(secretCloudflareZoneToken)
	certAuthToken := credentials.GetSecret(secretCertAuthToken)

	var cert *tls.Certificate
	if request.Domain == "localhost" || shimCfg.TLSMode == "self-signed" {
		cert, err = Certificate(request.Key, domains...)
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert: %w", err)
		}
	} else if shimCfg.TLSMode == "cert-proxy" {
		if shimCfg.ControlPlane == "" {
			return nil, fmt.Errorf("cert-proxy requires control-plane URL")
		}
		var httpChallengeDomains []string
		var listenPort int
		if shimCfg.TLSChallengeMode == "http" {
			httpChallengeDomains = []string{request.Domain}
			listenPort = bootstate.HTTPChallengePort
		}
		requestCertificate := func() (*tls.Certificate, error) {
			mgr, err := NewCertProxyManager(
				domains, bootstate.CacheDir, shimCfg.ControlPlane, request.Key,
				httpChallengeDomains, listenPort, certAuthToken,
			)
			if err != nil {
				return nil, fmt.Errorf("creating cert proxy manager: %w", err)
			}
			return retryCertificate(ctx, mgr.Certificate, certProxyRetryInterval)
		}
		if shimCfg.TLSChallengeMode == "http" {
			cert, err = withHTTP01Firewall(requestCertificate)
		} else {
			cert, err = requestCertificate()
		}
		if err != nil {
			return nil, fmt.Errorf("obtaining cert via cert-proxy: %w", err)
		}
	} else {
		dir := lego.LEDirectoryProduction
		if shimCfg.TLSEnv == "staging" {
			dir = lego.LEDirectoryStaging
		}
		mgr, err := NewCertManager(
			domains, shimCfg.Email, bootstate.CacheDir, dir,
			ChallengeMode(shimCfg.TLSChallengeMode),
			bootstate.ShimListenPort, request.Key,
			cfDNS, cfZone,
		)
		if err != nil {
			return nil, fmt.Errorf("creating ACME cert manager: %w", err)
		}
		cert, err = retryCertificate(ctx, mgr.Certificate, acmeRetryInterval)
		if err != nil {
			return nil, fmt.Errorf("obtaining cert via ACME: %w", err)
		}
	}

	return certificateForKey(cert, request.Key)
}

func retryCertificate(ctx context.Context, fn func() (*tls.Certificate, error), interval time.Duration) (*tls.Certificate, error) {
	for attempt := range maxCertRetries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cert, err := fn()
		if err == nil {
			return cert, nil
		}
		log.Printf("Certificate request failed (attempt %d/%d), retrying in %s: %v", attempt+1, maxCertRetries, interval, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
	return nil, fmt.Errorf("certificate request failed after %d attempts", maxCertRetries)
}

func withHTTP01Firewall(requestCertificate func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	return withHTTP01FirewallWith(firewall.Apply, requestCertificate)
}

func withHTTP01FirewallWith(run func(string) error, requestCertificate func() (*tls.Certificate, error)) (cert *tls.Certificate, retErr error) {
	if err := run("add rule inet tinfoil http01 tcp dport 80 accept\n"); err != nil {
		return nil, fmt.Errorf("opening HTTP-01 firewall: %w", err)
	}
	defer func() {
		if err := run("flush chain inet tinfoil http01\n"); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("closing HTTP-01 firewall: %w", err))
		}
	}()

	return requestCertificate()
}

// Bind the returned certificate to the key used for this boot's attestation.
// This also checks certificates returned from the managers' caches.
func certificateForKey(cert *tls.Certificate, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate has no leaf")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("certificate does not match boot identity")
	}
	cert.PrivateKey = key
	return cert, nil
}
