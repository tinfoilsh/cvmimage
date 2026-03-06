package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	log "github.com/sirupsen/logrus"
)

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}
func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

var (
	ChallengeModeTLSALPN01 ChallengeMode = "tls"
	ChallengeModeDNS01     ChallengeMode = "dns"
	ChallengeModeHTTP01    ChallengeMode = "http"
)

type ChallengeMode string

type CertManager struct {
	config         *lego.Config
	client         *lego.Client
	cacheDir       string
	certSigningKey *ecdsa.PrivateKey
	domains        []string
}

func NewCertManager(
	domains []string,
	email, cacheDir, caDir string,
	challengeMode ChallengeMode,
	port int,
	privateKey *ecdsa.PrivateKey,
	cloudflareAuthToken, cloudflareZoneToken string,
) (*CertManager, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	acmeUserPrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	user := &acmeUser{Email: email, key: acmeUserPrivateKey}
	config := &lego.Config{
		CADirURL:   caDir,
		User:       user,
		HTTPClient: http.DefaultClient,
		Certificate: lego.CertificateConfig{
			KeyType: certcrypto.EC384,
			Timeout: 30 * time.Second,
		},
	}
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	switch challengeMode {
	case ChallengeModeTLSALPN01:
		if err := client.Challenge.SetTLSALPN01Provider(
			tlsalpn01.NewProviderServer("", fmt.Sprintf("%d", port)),
		); err != nil {
			return nil, fmt.Errorf("failed to set TLS-ALPN-01 provider: %w", err)
		}
	case ChallengeModeHTTP01:
		// HTTP-01 challenge server listens on the same port as the main HTTPS server.
		if err := client.Challenge.SetHTTP01Provider(
			http01.NewProviderServer("", fmt.Sprintf("%d", port)),
		); err != nil {
			return nil, fmt.Errorf("failed to set HTTP-01 provider: %w", err)
		}
	case ChallengeModeDNS01:
		dnsConfig := cloudflare.NewDefaultConfig()
		dnsConfig.AuthToken = cloudflareAuthToken
		dnsConfig.ZoneToken = cloudflareZoneToken
		dnsProvider, err := cloudflare.NewDNSProviderConfig(dnsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Cloudflare DNS provider: %w", err)
		}
		if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
			return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid challenge mode: %s", challengeMode)
	}

	// Only register if certificate doesn't exist in cache
	certFile := filepath.Join(cacheDir, "cert.pem")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Debug("Registering ACME account")
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("failed to register account: %w", err)
		}
		user.Registration = reg
	} else {
		log.Debug("Certificate exists in cache, skipping ACME registration")
	}

	return &CertManager{
		domains:        domains,
		config:         config,
		client:         client,
		cacheDir:       cacheDir,
		certSigningKey: privateKey,
	}, nil
}

func (m *CertManager) Certificate() (*tls.Certificate, error) {
	certFile := filepath.Join(m.cacheDir, "cert.pem")
	keyFile := filepath.Join(m.cacheDir, "key.pem")

	if _, err := os.Stat(certFile); err == nil {
		log.Info("Certificate found in cache, using cached certificate")
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load cached certificate: %w", err)
		}
		return &cert, nil
	}

	log.Debugf("Requesting certificate for: %v", m.domains)
	certResource, err := m.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    m.domains,
		Bundle:     true,
		PrivateKey: m.certSigningKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Encode ECDSA key to PEM
	keyBytes, err := encodeECDSAKeyToPEM(m.certSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	// Write to cache
	if err := os.WriteFile(certFile, certResource.Certificate, 0644); err != nil {
		return nil, fmt.Errorf("failed to write certificate to cache: %w", err)
	}
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key to cache: %w", err)
	}

	cert, err := tls.X509KeyPair(certResource.Certificate, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Debug("Certificate obtained")
	return &cert, nil
}

// encodeECDSAKeyToPEM encodes an ECDSA private key to PEM format
func encodeECDSAKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	}
	return pem.EncodeToMemory(pemBlock), nil
}
