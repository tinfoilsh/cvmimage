package config

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/creasty/defaults"
	"gopkg.in/yaml.v3"
)

type Config struct {
	UpstreamPort int `yaml:"upstream-port"`
	// UpstreamContainer names the workload container the shim proxies to.
	// Optional: tinfoil-boot defaults it to the first entry of containers[].
	UpstreamContainer string `yaml:"upstream-container,omitempty"`
	// Model is the attestation-bound deployment identifier sent to the control
	// plane for per-model authorization policy.
	Model string `yaml:"model,omitempty"`

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
	// If present but empty, no endpoints require authentication unless Authenticated is true,
	// in which case validation rejects the configuration.
	// Supports the same wildcard patterns as Paths (e.g. "/v1/*").
	AuthenticatedEndpoints *[]string `yaml:"authenticated-endpoints"`

	RateLimit float64 `yaml:"rate-limit"`
	RateBurst int     `yaml:"rate-burst"`
	Email     string  `yaml:"email" default:"tls@tinfoil.sh"`

	PublishAttestation bool `yaml:"publish-attestation" default:"true"`
	DummyAttestation   bool `yaml:"dummy-attestation" default:"false"`

	// ExpectedGPUs is copied from the attested top-level boot config so the
	// shim does not need to probe hardware on its public request path.
	ExpectedGPUs int `yaml:"expected-gpus" default:"0"`
}

var shimConfigFields = configYAMLFields()

func configYAMLFields() map[string]bool {
	fields := make(map[string]bool)
	typeOfConfig := reflect.TypeOf(Config{})
	for index := range typeOfConfig.NumField() {
		name, _, _ := strings.Cut(typeOfConfig.Field(index).Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			fields[name] = true
		}
	}
	return fields
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("shim config must be a mapping")
	}
	for index := 0; index < len(node.Content); index += 2 {
		field := node.Content[index].Value
		if !shimConfigFields[field] {
			return fmt.Errorf("unknown shim field %q", field)
		}
	}
	type rawConfig Config
	raw := rawConfig(*c)
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*c = Config(raw)
	return nil
}

const SecretMetricsAPIKey = "METRICS_API_KEY"

type Metadata struct {
	ID     string `yaml:"id"`
	Domain string `yaml:"domain"`
	Image  string `yaml:"image"`
	CPU    string `yaml:"cpu"`
	GPU    string `yaml:"gpu"`
	Repo   string `yaml:"repo,omitempty"`
	Digest string `yaml:"digest,omitempty"`
	// Extra preserves operator metadata that tinfoild merges into this
	// unmeasured document. Only the security-sensitive network block is closed.
	Extra map[string]yaml.Node `yaml:",inline"`
}

type ExternalNetworkConfig struct {
	Address string `yaml:"address"`
	Gateway string `yaml:"gateway"`
}

type ExternalConfig struct {
	MetricsAPIKey string                 `yaml:"-"`
	Env           map[string]string      `yaml:"env"`
	Secrets       map[string]string      `yaml:"secrets"`
	Metadata      Metadata               `yaml:"metadata"`
	VaultToken    string                 `yaml:"vault-token,omitempty"`
	Network       *ExternalNetworkConfig `yaml:"network"`

	// tinfoild preserves operator-owned top-level external data. Keep accepting
	// those unrelated keys while KnownFields rejects unknown network fields.
	Extra map[string]yaml.Node `yaml:",inline"`
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

// DecodeExternal strictly decodes typed external-config sections. Unknown
// operator-owned top-level keys remain opaque through ExternalConfig.Extra.
func DecodeExternal(data []byte) (*ExternalConfig, error) {
	if _, err := decodeYAMLDocument(data); err != nil {
		return nil, fmt.Errorf("failed to decode external config: %v", err)
	}
	var config ExternalConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode external config: %v", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("failed to decode external config: multiple YAML documents")
		}
		return nil, fmt.Errorf("failed to decode external config: %v", err)
	}
	if err := defaults.Set(&config); err != nil {
		return nil, fmt.Errorf("failed to set external config defaults: %v", err)
	}
	if err := config.validateBounds(); err != nil {
		return nil, fmt.Errorf("invalid external config: %v", err)
	}

	config.MetricsAPIKey = config.GetSecret(SecretMetricsAPIKey)
	return &config, nil
}

// Decode populates a Config from a yaml.Node (a parsed YAML subtree),
// applies defaults, and validates. Used by boot, which has already parsed
// the parent config and needs to type the `shim:` subsection.
func Decode(n *yaml.Node) (*Config, error) {
	if err := validateYAMLTree(n); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
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
	if c.Authenticated {
		controlPlane, err := url.Parse(c.ControlPlane)
		if err != nil || controlPlane.Scheme != "https" || controlPlane.Hostname() == "" || controlPlane.User != nil || controlPlane.ForceQuery || controlPlane.RawQuery != "" || controlPlane.Fragment != "" {
			return fmt.Errorf("authenticated shim requires a valid HTTPS control plane URL")
		}
		if c.Model == "" {
			return fmt.Errorf("authenticated shim requires an attestation-bound model identifier")
		}
		if c.AuthenticatedEndpoints != nil && len(*c.AuthenticatedEndpoints) == 0 {
			return fmt.Errorf("authenticated shim must protect at least one endpoint")
		}
	}
	if err := validatePathPatterns("paths", c.Paths); err != nil {
		return err
	}
	if c.AuthenticatedEndpoints != nil {
		if err := validatePathPatterns("authenticated-endpoints", *c.AuthenticatedEndpoints); err != nil {
			return err
		}
	}
	return nil
}

func validatePathPatterns(field string, patterns []string) error {
	for index, pattern := range patterns {
		if pattern == "" || pattern[0] != '/' || strings.ContainsAny(pattern, "?#\\%") || path.Clean(pattern) != pattern {
			return fmt.Errorf("%s[%d] %q is not a canonical absolute request path", field, index, pattern)
		}
		if strings.Contains(pattern, "*") && (!strings.HasSuffix(pattern, "/*") || strings.Count(pattern, "*") != 1) {
			return fmt.Errorf("%s[%d] %q uses unsupported wildcard syntax; only a trailing /* is allowed", field, index, pattern)
		}
	}
	return nil
}

// Load reads and parses both config files from disk.
func Load(configFile, externalConfigFile string) (*Config, *ExternalConfig, error) {
	configBytes, err := readConfigFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	node, err := decodeYAMLDocument(configBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}
	config, err := Decode(node)
	if err != nil {
		return nil, nil, err
	}

	externalConfigBytes, err := readConfigFile(externalConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read external config file: %v", err)
	}
	externalConfig, err := DecodeExternal(externalConfigBytes)
	if err != nil {
		return nil, nil, err
	}
	return config, externalConfig, nil
}
