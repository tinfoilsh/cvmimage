package config

import (
	"fmt"
	"os"
	"slices"

	"github.com/creasty/defaults"
	"gopkg.in/yaml.v3"
)

type Config struct {
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

	RateLimit float64 `yaml:"rate-limit"`
	RateBurst int     `yaml:"rate-burst"`
	Email     string  `yaml:"email" default:"tls@tinfoil.sh"`

	PublishAttestation bool `yaml:"publish-attestation" default:"true"`
	DummyAttestation   bool `yaml:"dummy-attestation" default:"false"`
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

// Decode populates a Config from a yaml.Node (a parsed YAML subtree),
// applies defaults, and validates. Used by boot, which has already parsed
// the parent config and needs to type the `shim:` subsection.
func Decode(n *yaml.Node) (*Config, error) {
	var config Config
	if err := defaults.Set(&config); err != nil {
		return nil, fmt.Errorf("failed to set defaults: %v", err)
	}
	if err := n.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *Config) Validate() error {
	if c.UpstreamPort == 0 {
		return fmt.Errorf("upstream port is not set")
	}
	if !slices.Contains([]string{"self-signed", "acme", "cert-proxy"}, c.TLSMode) {
		return fmt.Errorf("invalid TLS mode: %s (must be self-signed, acme, or cert-proxy)", c.TLSMode)
	}
	if !slices.Contains([]string{"production", "staging"}, c.TLSEnv) {
		return fmt.Errorf("invalid TLS environment: %s (must be production or staging)", c.TLSEnv)
	}
	if !slices.Contains([]string{"tls", "dns", "http"}, c.TLSChallengeMode) {
		return fmt.Errorf("invalid TLS challenge mode: %s (must be tls, dns, or http)", c.TLSChallengeMode)
	}
	if c.TLSWildcard && c.TLSChallengeMode != "dns" {
		return fmt.Errorf("tls-wildcard requires tls-challenge: dns (wildcard certs cannot use %s challenge)", c.TLSChallengeMode)
	}
	return nil
}

// Load reads and parses both config files from disk.
func Load(configFile, externalConfigFile string) (*Config, *ExternalConfig, error) {
	configBytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(configBytes, &node); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}
	config, err := Decode(&node)
	if err != nil {
		return nil, nil, err
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

	return config, &externalConfig, nil
}
