package config

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/creasty/defaults"
	sharedconfig "github.com/tinfoilsh/tinfoil-config"
)

type Config = sharedconfig.ShimConfig

const SecretMetricsAPIKey = "METRICS_API_KEY"

const SourceLocal = "local"

type Metadata struct {
	ConfigSource string `json:"config_source"`

	ID     string `json:"id"`
	Domain string `json:"domain"`
	Image  string `json:"image"`
	CPU    string `json:"cpu"`
	GPU    string `json:"gpu"`
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
	// Extra preserves operator metadata that tinfoild merges into this
	// unmeasured document. The network block rejects unknown fields.
	Extra map[string]jsontext.Value `json:",embed"`
}

type ExternalNetworkConfig struct {
	Address string `json:"address"`
	Gateway string `json:"gateway"`
}

// ExternalConfig is the unmeasured document tinfoild writes for each launch.
// Its JSON form is a contract with tinfoild's writer; the golden document in
// testdata is the copy both sides test against.
type ExternalConfig struct {
	MetricsAPIKey string                 `json:"-"`
	Env           map[string]string      `json:"env"`
	Secrets       map[string]string      `json:"secrets"`
	Metadata      Metadata               `json:"metadata"`
	Network       *ExternalNetworkConfig `json:"network"`
	// ShutdownToken authorizes the host's shutdown request. tinfoild generates
	// it per launch; an empty token disables the endpoint.
	ShutdownToken string `json:"shutdown_token"`

	// tinfoild preserves operator-owned top-level external data. Keep accepting
	// those unrelated keys while the network block rejects unknown fields.
	Extra map[string]jsontext.Value `json:",embed"`
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
	var config ExternalConfig
	if err := decodeJSONObject(data, &config, json.RejectUnknownMembers(true)); err != nil {
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

// durationText writes a duration as the text time.ParseDuration reads, since
// JSON has no type for one.
var durationText = json.JoinOptions(
	json.WithMarshalers(json.MarshalToFunc(func(encoder *jsontext.Encoder, value time.Duration) error {
		return encoder.WriteToken(jsontext.String(value.String()))
	})),
	json.WithUnmarshalers(json.UnmarshalFromFunc(func(decoder *jsontext.Decoder, value *time.Duration) error {
		var text string
		if err := json.UnmarshalDecode(decoder, &text); err != nil {
			return err
		}
		duration, err := time.ParseDuration(text)
		*value = duration
		return err
	})),
)

// Encode writes shim settings as the file that Decode reads.
func Encode(config *Config) ([]byte, error) {
	return json.Marshal(config, durationText)
}

// Decode reads shim settings, applies defaults, and validates. The settings
// file is one this runtime derives from the measured config and writes itself
// with Encode.
func Decode(data []byte) (*Config, error) {
	var config Config
	if err := defaults.Set(&config); err != nil {
		return nil, fmt.Errorf("failed to set defaults: %v", err)
	}
	if err := decodeJSONObject(data, &config, json.RejectUnknownMembers(true), durationText); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

// Load reads and parses both config files from disk.
func Load(configFile, externalConfigFile string) (*Config, *ExternalConfig, error) {
	configBytes, err := readConfigFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	config, err := Decode(configBytes)
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
