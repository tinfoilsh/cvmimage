package config

import (
	"bytes"
	"fmt"
	"io"

	"github.com/creasty/defaults"
	sharedconfig "github.com/tinfoilsh/tinfoil-config"
	"gopkg.in/yaml.v3"
)

type Config = sharedconfig.ShimConfig

const SecretMetricsAPIKey = "METRICS_API_KEY"

type Metadata struct {
	ID     string `yaml:"id"`
	Domain string `yaml:"domain"`
	Image  string `yaml:"image"`
	CPU    string `yaml:"cpu"`
	GPU    string `yaml:"gpu"`
	Repo   string `yaml:"repo,omitempty"`
	Tag    string `yaml:"tag,omitempty"`
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
	return sharedconfig.DecodeShim(n)
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
