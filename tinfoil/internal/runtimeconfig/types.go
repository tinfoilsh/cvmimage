package runtimeconfig

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	shimconfig "tinfoil/internal/config"
)

const (
	ReservedDebugContainerName = "tinfoil-debug-toolbox"
	ReservedDebugPort          = "2222/tcp"
	ReservedDebugHostPort      = 2222
	ReservedDebugSerialDevice  = "/dev/hvc1"
)

type Config struct {
	CVMVersion string                  `yaml:"cvm-version"`
	ShimRaw    yaml.Node               `yaml:"shim"`
	ShimCfg    *shimconfig.Config      `yaml:"-"`
	CVMNetwork CVMNetworkConfig        `yaml:"cvm-network"`
	Networks   map[string]*NetworkSpec `yaml:"networks"`
	CPUs       int                     `yaml:"cpus"`
	Memory     int                     `yaml:"memory"`
	GPUs       int                     `yaml:"gpus"`
	Models     []ModelSpec             `yaml:"models"`
	Containers []Container             `yaml:"containers"`
	VaultURL   string                  `yaml:"vault-url,omitempty"`
}

type CVMNetworkConfig struct {
	InboundPorts []int `yaml:"inbound-ports"`
}

type NetworkSpec struct {
	Egress string   `yaml:"egress"`
	Allow  []string `yaml:"allow"`
}

func (n *NetworkSpec) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		if node.Tag != "!!null" {
			return fmt.Errorf("network entry must be a mapping or null")
		}
		n.Egress = "closed"
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("network entry must be a mapping")
	}
	seen := map[string]bool{}
	for index := 0; index < len(node.Content); index += 2 {
		field := node.Content[index].Value
		if seen[field] {
			return fmt.Errorf("duplicate network field %q", field)
		}
		seen[field] = true
		if field != "egress" && field != "allow" {
			return fmt.Errorf("unknown network field %q", field)
		}
	}
	type alias NetworkSpec
	var raw alias
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*n = NetworkSpec(raw)
	if n.Egress == "" {
		n.Egress = "closed"
	}
	return nil
}

type ModelSpec struct {
	Name      string `yaml:"name,omitempty"`
	Repo      string `yaml:"repo,omitempty"`
	MPK       string `yaml:"mpk,omitempty"`
	MWP       string `yaml:"mwp,omitempty"`
	EMWP      string `yaml:"emwp,omitempty"`
	KeySecret string `yaml:"key-secret,omitempty"`
}

type Container struct {
	Name        string            `yaml:"name"`
	Image       string            `yaml:"image"`
	Command     []string          `yaml:"command,omitempty"`
	Entrypoint  []string          `yaml:"entrypoint,omitempty"`
	WorkingDir  string            `yaml:"working_dir,omitempty"`
	User        string            `yaml:"user,omitempty"`
	Env         []interface{}     `yaml:"env,omitempty"`
	Secrets     []string          `yaml:"secrets,omitempty"`
	Volumes     []string          `yaml:"volumes,omitempty"`
	Devices     []string          `yaml:"devices,omitempty"`
	CapAdd      []string          `yaml:"cap_add,omitempty"`
	Runtime     string            `yaml:"runtime,omitempty"`
	Networks    []string          `yaml:"networks,omitempty"`
	IPC         string            `yaml:"ipc,omitempty"`
	PidMode     string            `yaml:"pid,omitempty"`
	GPUs        interface{}       `yaml:"gpus,omitempty"`
	ShmSize     string            `yaml:"shm_size,omitempty"`
	Memory      string            `yaml:"memory,omitempty"`
	CPUs        float64           `yaml:"cpus,omitempty"`
	Tmpfs       map[string]string `yaml:"tmpfs,omitempty"`
	ReadOnly    *bool             `yaml:"read_only,omitempty"`
	PidsLimit   *int64            `yaml:"pids_limit,omitempty"`
	Restart     string            `yaml:"restart,omitempty"`
	StopSignal  string            `yaml:"stop_signal,omitempty"`
	StopTimeout *int              `yaml:"stop_timeout,omitempty"`
	Healthcheck *Healthcheck      `yaml:"healthcheck,omitempty"`
	inputFields containerInputFields
}

type containerInputFields struct {
	privileged  bool
	capDrop     bool
	securityOpt bool
}

var containerFields = map[string]bool{
	"name": true, "image": true, "command": true, "entrypoint": true,
	"working_dir": true, "user": true, "env": true, "secrets": true,
	"volumes": true, "devices": true, "cap_add": true, "runtime": true,
	"networks": true, "ipc": true, "pid": true, "gpus": true,
	"shm_size": true, "memory": true, "cpus": true, "tmpfs": true,
	"read_only": true, "pids_limit": true, "restart": true,
	"stop_signal": true, "stop_timeout": true, "healthcheck": true,
	"privileged": true, "cap_drop": true, "security_opt": true,
}

func (c *Container) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("container entry must be a mapping")
	}
	var fields containerInputFields
	seen := map[string]bool{}
	for index := 0; index < len(node.Content); index += 2 {
		field := node.Content[index].Value
		if field == "<<" {
			return fmt.Errorf("container YAML merge keys are unsupported")
		}
		if seen[field] {
			return fmt.Errorf("duplicate container field %q", field)
		}
		seen[field] = true
		if !containerFields[field] {
			return fmt.Errorf("unknown container field %q", field)
		}
		switch field {
		case "privileged":
			fields.privileged = true
		case "cap_drop":
			fields.capDrop = true
		case "security_opt":
			fields.securityOpt = true
		}
	}
	type rawContainer Container
	var raw rawContainer
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*c = Container(raw)
	c.inputFields = fields
	return nil
}

type Healthcheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval,omitempty"`
	Timeout     string   `yaml:"timeout,omitempty"`
	Retries     int      `yaml:"retries,omitempty"`
	StartPeriod string   `yaml:"start_period,omitempty"`
}

func (h *Healthcheck) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("healthcheck must be a mapping")
	}
	allowed := map[string]bool{
		"test": true, "interval": true, "timeout": true,
		"retries": true, "start_period": true,
	}
	seen := map[string]bool{}
	for index := 0; index < len(node.Content); index += 2 {
		field := node.Content[index].Value
		if seen[field] {
			return fmt.Errorf("duplicate healthcheck field %q", field)
		}
		seen[field] = true
		if !allowed[field] {
			return fmt.Errorf("unknown healthcheck field %q", field)
		}
	}
	type rawHealthcheck Healthcheck
	var raw rawHealthcheck
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*h = Healthcheck(raw)
	return nil
}

func ReservedDebugRuntimeEnabled(containerName string, debug bool) bool {
	return debug && containerName == ReservedDebugContainerName
}

func Decode(data []byte, debug bool) (*Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parsing config: multiple YAML documents")
		}
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	shimCfg, err := shimconfig.Decode(&config.ShimRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing shim config: %w", err)
	}
	shimCfg.ExpectedGPUs = config.GPUs
	if shimCfg.UpstreamContainer == "" && len(config.Containers) > 0 {
		shimCfg.UpstreamContainer = config.Containers[0].Name
	}
	config.ShimCfg = shimCfg
	setNetworkDefaults(&config)
	if err := Validate(&config, debug); err != nil {
		return nil, err
	}
	return &config, nil
}

func setNetworkDefaults(config *Config) {
	for name, spec := range config.Networks {
		if spec == nil {
			config.Networks[name] = &NetworkSpec{Egress: "closed"}
		}
	}
}

func ShimUpstreamSet(config *Config) bool {
	return config.ShimCfg != nil && config.ShimCfg.UpstreamContainer != ""
}

func HasReservedDebugContainer(config *Config) bool {
	for _, container := range config.Containers {
		if container.Name == ReservedDebugContainerName {
			return true
		}
	}
	return false
}

func validNamedVolume(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && strings.ContainsRune("_.-", rune(character)) {
			continue
		}
		return false
	}
	return true
}
