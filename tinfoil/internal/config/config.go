package config

import (
	"fmt"
	"os"
	"slices"

	"github.com/creasty/defaults"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenPort   int `yaml:"listen-port" default:"443"`
	UpstreamPort int `yaml:"upstream-port"`

	Paths         []string `yaml:"paths"`
	OriginDomains []string `yaml:"origins"`

	TLSMode          string `yaml:"tls-mode" default:"cert-proxy"`      // self-signed | acme | cert-proxy
	TLSEnv           string `yaml:"tls-env" default:"production"`       // production | staging
	TLSChallengeMode string `yaml:"tls-challenge" default:"dns"`        // tls | dns | http
	TLSWildcard      bool   `yaml:"tls-wildcard" default:"false"`       // include wildcard SAN (*.domain)
	TLSOwnSANDomain  bool   `yaml:"tls-own-san-domain" default:"false"` // use own domain for encoded SANs instead of tinfoil.sh

	ControlPlane string `yaml:"control-plane" default:"https://api.tinfoil.sh"`
	// Authenticated enables API key validation against the control plane.
	// When false, no API key checks are performed regardless of AuthenticatedEndpoints.
	Authenticated bool `yaml:"authenticated" default:"false"`
	// AuthenticatedEndpoints is the list of endpoint patterns that require API key authentication.
	// If absent (nil), defaults to ["/v1/chat/completions"] for backwards compatibility.
	// If present but empty, no endpoints require authentication.
	// Supports the same wildcard patterns as Paths (e.g. "/v1/*").
	AuthenticatedEndpoints *[]string `yaml:"authenticated-endpoints"`

	RateLimit   float64 `yaml:"rate-limit"`
	RateBurst   int     `yaml:"rate-burst"`
	CacheDir    string  `yaml:"cache-dir" default:"/mnt/ramdisk/tfshim-cache"`
	Email       string  `yaml:"email" default:"tls@tinfoil.sh"`
	HPKEKeyFile string  `yaml:"hpke-key-file" default:"/mnt/ramdisk/hpke_key.json"`

	PublishAttestation bool `yaml:"publish-attestation" default:"true"`
	DummyAttestation   bool `yaml:"dummy-attestation" default:"false"`

	Verbose bool `yaml:"verbose"`
}

const (
	SecretMetricsAPIKey = "METRICS_API_KEY"
	SecretACPIAPIKey    = "ACPI_API_KEY"
)

type Metadata struct {
	ID     string `yaml:"id"`
	Domain string `yaml:"domain"`
	Image  string `yaml:"image"`
	GPU    string `yaml:"gpu"`
}

type ExternalConfig struct {
	MetricsAPIKey string
	ACPIAPIKey    string

	Env      map[string]string `yaml:"env"`
	Secrets  map[string]string `yaml:"secrets"`
	Metadata Metadata          `yaml:"metadata"`
}

func (e *ExternalConfig) GetSecret(key string) string {
	if e == nil || e.Secrets == nil {
		return ""
	}
	v := e.Secrets[key]
	if v == "null" {
		return ""
	}
	return v
}

// Load loads the config from the given files
func Load(configFile, externalConfigFile string) (*Config, *ExternalConfig, error) {
	var config Config
	if err := defaults.Set(&config); err != nil {
		return nil, nil, fmt.Errorf("failed to set defaults: %v", err)
	}

	configBytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	if config.UpstreamPort == 0 {
		return nil, nil, fmt.Errorf("upstream port is not set")
	}
	if !slices.Contains([]string{"self-signed", "acme", "cert-proxy"}, config.TLSMode) {
		return nil, nil, fmt.Errorf("invalid TLS mode: %s (must be self-signed, acme, or cert-proxy)", config.TLSMode)
	}
	if !slices.Contains([]string{"production", "staging"}, config.TLSEnv) {
		return nil, nil, fmt.Errorf("invalid TLS environment: %s (must be production or staging)", config.TLSEnv)
	}
	if !slices.Contains([]string{"tls", "dns", "http"}, config.TLSChallengeMode) {
		return nil, nil, fmt.Errorf("invalid TLS challenge mode: %s (must be tls, dns, or http)", config.TLSChallengeMode)
	}
	if config.TLSWildcard && config.TLSChallengeMode != "dns" {
		return nil, nil, fmt.Errorf("tls-wildcard requires tls-challenge: dns (wildcard certs cannot use %s challenge)", config.TLSChallengeMode)
	}

	externalConfigBytes, err := os.ReadFile(externalConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read external config file: %v", err)
	}
	var externalConfig ExternalConfig
	if err := yaml.Unmarshal(externalConfigBytes, &externalConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal external config: %v", err)
	}
	if err := defaults.Set(&externalConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to set defaults: %v", err)
	}

	externalConfig.MetricsAPIKey = externalConfig.GetSecret(SecretMetricsAPIKey)
	externalConfig.ACPIAPIKey = externalConfig.GetSecret(SecretACPIAPIKey)

	return &config, &externalConfig, nil
}
