package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

const certProxyTimeout = 5 * time.Minute

// CertProxyManager obtains certificates from a control plane proxy.
// When httpChallengeDomains is set, it uses a two-phase relay: the control plane
// handles DNS-01 for encoded SANs while the shim serves HTTP-01 for the base domain.
type CertProxyManager struct {
	domains              []string
	cacheDir             string
	controlPlaneURL      string
	privateKey           *ecdsa.PrivateKey
	httpChallengeDomains []string // domains needing HTTP-01 (empty = pure DNS proxy)
	listenPort           int      // port for temp HTTP-01 challenge server
	certAuthToken        string
}

// NewCertProxyManager creates a new certificate manager that obtains certs via control plane.
// Pass non-empty httpChallengeDomains to enable mixed challenge relay.
func NewCertProxyManager(
	domains []string,
	cacheDir string,
	controlPlaneURL string,
	privateKey *ecdsa.PrivateKey,
	httpChallengeDomains []string,
	listenPort int,
	certAuthToken string,
) (*CertProxyManager, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	if controlPlaneURL == "" {
		return nil, fmt.Errorf("control plane URL is required")
	}
	parsedURL, err := url.Parse(controlPlaneURL)
	if err != nil {
		return nil, fmt.Errorf("invalid control plane URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("control plane URL must use HTTPS scheme")
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &CertProxyManager{
		domains:              domains,
		cacheDir:             cacheDir,
		controlPlaneURL:      controlPlaneURL,
		privateKey:           privateKey,
		httpChallengeDomains: httpChallengeDomains,
		listenPort:           listenPort,
		certAuthToken:        certAuthToken,
	}, nil
}

// Certificate returns a TLS certificate, either from cache or by requesting from control plane
func (m *CertProxyManager) Certificate() (*tls.Certificate, error) {
	certFile := filepath.Join(m.cacheDir, "cert.pem")
	keyFile := filepath.Join(m.cacheDir, "key.pem")

	// Check cache first
	if _, err := os.Stat(certFile); err == nil {
		log.Info("Certificate found in cache, using cached certificate")
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load cached certificate: %w", err)
		}
		return &cert, nil
	}

	return m.obtainCertificate(certFile, keyFile)
}

func (m *CertProxyManager) obtainCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	log.Debugf("Requesting certificate via cert proxy for: %v", m.domains)

	csrPEM, err := m.createCSR()
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	var certPEM []byte
	if len(m.httpChallengeDomains) > 0 {
		certPEM, err = m.obtainWithHTTPRelay(csrPEM)
	} else {
		certPEM, err = m.requestCertificate(csrPEM)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate from control plane: %w", err)
	}

	keyBytes, err := encodeECDSAKeyToPEM(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to write certificate to cache: %w", err)
	}
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key to cache: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Info("Certificate obtained via cert proxy")
	return &cert, nil
}

// obtainWithHTTPRelay uses the two-phase relay protocol:
// Phase 1: send CSR + http_domains, get challenge tokens back
// Phase 2: serve HTTP-01 challenges, then call /cert/ready to get the certificate
func (m *CertProxyManager) obtainWithHTTPRelay(csrPEM []byte) ([]byte, error) {
	log.Infof("Using mixed challenge relay (HTTP-01 for %v)", m.httpChallengeDomains)

	// Phase 1: request order with HTTP challenge domains
	certURL, err := url.JoinPath(m.controlPlaneURL, "api", "shim", "cert")
	if err != nil {
		return nil, fmt.Errorf("failed to construct cert URL: %w", err)
	}

	reqBody, err := json.Marshal(struct {
		CSR         string   `json:"csr"`
		HTTPDomains []string `json:"http_domains"`
	}{
		CSR:         string(csrPEM),
		HTTPDomains: m.httpChallengeDomains,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{Timeout: certProxyTimeout}
	resp, err := client.Post(certURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("phase 1 request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read phase 1 response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phase 1 error (status %d): %s", resp.StatusCode, string(body))
	}

	var phase1 struct {
		OrderID    string `json:"order_id"`
		Challenges []struct {
			Domain           string `json:"domain"`
			Token            string `json:"token"`
			KeyAuthorization string `json:"key_authorization"`
		} `json:"http_challenges"`
	}
	if err := json.Unmarshal(body, &phase1); err != nil {
		return nil, fmt.Errorf("failed to parse phase 1 response: %w", err)
	}

	if phase1.OrderID == "" {
		return nil, fmt.Errorf("phase 1 returned no order_id")
	}

	// Serve HTTP-01 challenges if any were returned (skip if control plane
	// handled all domains via DNS-01, e.g. domains already validated).
	if len(phase1.Challenges) > 0 {
		mux := http.NewServeMux()
		for _, ch := range phase1.Challenges {
			keyAuth := ch.KeyAuthorization
			mux.HandleFunc("/.well-known/acme-challenge/"+ch.Token, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(keyAuth))
			})
			tokenPreview := ch.Token
			if len(tokenPreview) > 8 {
				tokenPreview = tokenPreview[:8]
			}
			log.Debugf("Serving HTTP-01 challenge for %s (token=%s...)", ch.Domain, tokenPreview)
		}
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       10 * time.Second,
		}

		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", m.listenPort))
		if err != nil {
			return nil, fmt.Errorf("failed to bind HTTP challenge server: %w", err)
		}
		go func() {
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Warnf("HTTP challenge server error: %v", err)
			}
		}()
		defer srv.Close()
	} else {
		log.Info("No HTTP-01 challenges returned, proceeding directly to phase 2")
	}

	// Phase 2: signal ready and get certificate
	readyURL, err := url.JoinPath(m.controlPlaneURL, "api", "shim", "cert", "ready")
	if err != nil {
		return nil, fmt.Errorf("failed to construct ready URL: %w", err)
	}

	readyBody, err := json.Marshal(struct {
		OrderID string `json:"order_id"`
	}{OrderID: phase1.OrderID})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ready request: %w", err)
	}

	resp2, err := client.Post(readyURL, "application/json", bytes.NewReader(readyBody))
	if err != nil {
		return nil, fmt.Errorf("phase 2 request failed: %w", err)
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read phase 2 response: %w", err)
	}
	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phase 2 error (status %d): %s", resp2.StatusCode, string(body2))
	}

	var phase2 struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body2, &phase2); err != nil {
		return nil, fmt.Errorf("failed to parse phase 2 response: %w", err)
	}
	if phase2.Certificate == "" {
		return nil, fmt.Errorf("phase 2 returned empty certificate")
	}

	return []byte(phase2.Certificate), nil
}

func (m *CertProxyManager) createCSR() ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: m.domains[0],
		},
		DNSNames: m.domains,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

func (m *CertProxyManager) requestCertificate(csrPEM []byte) ([]byte, error) {
	certURL, err := url.JoinPath(m.controlPlaneURL, "api", "shim", "cert")
	if err != nil {
		return nil, fmt.Errorf("failed to construct cert URL: %w", err)
	}

	reqBody := struct {
		CSR   string `json:"csr"`
		Token string `json:"token,omitempty"`
	}{
		CSR:   string(csrPEM),
		Token: m.certAuthToken,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{Timeout: certProxyTimeout}
	resp, err := client.Post(certURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request to control plane: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned error (status %d): %s", resp.StatusCode, string(body))
	}

	var certResp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if certResp.Certificate == "" {
		return nil, fmt.Errorf("control plane returned empty certificate")
	}

	return []byte(certResp.Certificate), nil
}
