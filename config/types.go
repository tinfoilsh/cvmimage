package tinfoilconfig

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

const (
	ReservedDebugContainerName = "tinfoil-debug-toolbox"
	ReservedDebugPort          = "2222/tcp"
	ReservedDebugHostPort      = 2222
	AttestedKeysContainerDir   = "/run/tinfoil/keys"
	KeyECDSAP256               = "ecdsa-p256"
	KeyEd25519                 = "ed25519"
	KeyX25519                  = "x25519"
)

// ValidationMode selects which producer is allowed to construct the config.
// WorkloadMode is for user-supplied measured YAML. HostDebugMode is only for
// YAML after tinfoild has injected its reserved debug toolbox.
type ValidationMode uint8

const (
	WorkloadMode ValidationMode = iota
	HostDebugMode
)

type Options struct {
	Mode ValidationMode
}

type Config struct {
	CVMVersion   string                  `yaml:"cvm-version"`
	CVMSource    *CVMSource              `yaml:"cvm-source,omitempty"`
	ShimRaw      yaml.Node               `yaml:"shim"`
	ShimCfg      *ShimConfig             `yaml:"-"`
	CVMNetwork   CVMNetworkConfig        `yaml:"cvm-network"`
	Networks     map[string]*NetworkSpec `yaml:"networks"`
	CPUs         int                     `yaml:"cpus"`
	Memory       int                     `yaml:"memory"`
	GPUs         int                     `yaml:"gpus"`
	Models       []ModelSpec             `yaml:"models"`
	Volumes      []VolumeSpec            `yaml:"volumes"`
	AttestedKeys []AttestedKey           `yaml:"attested-keys,omitempty"`
	Containers   []Container             `yaml:"containers"`
	KeyserverURL string                  `yaml:"keyserver-url,omitempty"`
}

type CVMSource struct {
	Repo      string `yaml:"repo"`
	Artifacts string `yaml:"artifacts"`
}

var DefaultCVMSource = CVMSource{Repo: "tinfoilsh/cvmimage", Artifacts: "https://images.tinfoil.sh/cvm"}

func (s *CVMSource) OrDefault() CVMSource {
	if s == nil {
		return DefaultCVMSource
	}
	return *s
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

type VolumeSpec struct {
	Name      string          `yaml:"name"`
	Exec      bool            `yaml:"exec,omitempty"`
	Owner     int             `yaml:"owner,omitempty"`
	KeySecret string          `yaml:"key-secret,omitempty"`
	Overlays  []VolumeOverlay `yaml:"overlays,omitempty"`
	// Size is the capacity of the disk backing the volume, such as "500GiB"
	// or "16TB" (see ParseSize). Empty leaves the size to the host's default.
	// The host allocates the disk once, on first launch; changing the size
	// afterwards does not resize it.
	Size string `yaml:"size,omitempty"`
}

// SizeBytes returns the declared Size in bytes, or 0 when the host default
// applies.
func (v *VolumeSpec) SizeBytes() (int64, error) {
	if v.Size == "" {
		return 0, nil
	}
	return ParseSize(v.Size)
}

// VolumeOverlay stacks a model pack under a writable directory on the volume:
// Source is a subtree of the Model pack, taken as the read-only lower layer,
// and the merged tree appears at Target inside the volume. Both paths are
// measured here rather than chosen at unlock, so no runtime caller can steer
// the mount.
type VolumeOverlay struct {
	Model  string `yaml:"model"`
	Source string `yaml:"source"`
	Target string `yaml:"target"`
}

type ModelSpec struct {
	Name      string `yaml:"name,omitempty"`
	Repo      string `yaml:"repo,omitempty"`
	MPK       string `yaml:"mpk,omitempty"`
	MWP       string `yaml:"mwp,omitempty"`
	EMWP      string `yaml:"emwp,omitempty"`
	KeySecret string `yaml:"key-secret,omitempty"`
	// Weights are never programs, so a pack is noexec unless declared otherwise.
	Exec bool `yaml:"exec,omitempty"`
	// Schema is the pack schema the pinned artifact was built with (0 = schema 1,
	// the original layout). Declarative for now; no consumer reads it yet.
	Schema int `yaml:"schema,omitempty"`
}

// AttestedKey declares a boot-generated key. The runtime exports PKCS#8 private
// and SPKI public PEM, and endorses full public SPKI DER in v3 attestation.
// UID and GID are measured numeric file ownership, defaulting to root.
type AttestedKey struct {
	ID  string `yaml:"id" json:"id"`
	Key string `yaml:"key" json:"key"`
	UID int    `yaml:"uid,omitempty" json:"uid"`
	GID int    `yaml:"gid,omitempty" json:"gid"`
}

type Container struct {
	Name         string            `yaml:"name"`
	Image        string            `yaml:"image"`
	CVMAdmin     bool              `yaml:"cvm_admin,omitempty"` // Delegates administration of the entire CVM.
	SealRegister bool              `yaml:"seal_register,omitempty"`
	Attestation  bool              `yaml:"attestation,omitempty"`
	Command      []string          `yaml:"command,omitempty"`
	Entrypoint   []string          `yaml:"entrypoint,omitempty"`
	WorkingDir   string            `yaml:"working_dir,omitempty"`
	User         string            `yaml:"user,omitempty"`
	Env          []interface{}     `yaml:"env,omitempty"`
	Secrets      []string          `yaml:"secrets,omitempty"`
	Models       []string          `yaml:"models,omitempty"`
	Keys         []string          `yaml:"keys,omitempty"`
	Volumes      []string          `yaml:"volumes,omitempty"`
	Devices      []string          `yaml:"devices,omitempty"`
	CapAdd       []string          `yaml:"cap_add,omitempty"`
	Runtime      string            `yaml:"runtime,omitempty"`
	Networks     []string          `yaml:"networks,omitempty"`
	Ports        []string          `yaml:"ports,omitempty"`
	IPC          string            `yaml:"ipc,omitempty"`
	PidMode      string            `yaml:"pid,omitempty"`
	GPUs         interface{}       `yaml:"gpus,omitempty"`
	ShmSize      string            `yaml:"shm_size,omitempty"`
	Memory       string            `yaml:"memory,omitempty"`
	CPUs         float64           `yaml:"cpus,omitempty"`
	Tmpfs        map[string]string `yaml:"tmpfs,omitempty"`
	ReadOnly     *bool             `yaml:"read_only,omitempty"`
	PidsLimit    *int64            `yaml:"pids_limit,omitempty"`
	Restart      string            `yaml:"restart,omitempty"`
	StopSignal   string            `yaml:"stop_signal,omitempty"`
	StopTimeout  *int              `yaml:"stop_timeout,omitempty"`
	Healthcheck  *Healthcheck      `yaml:"healthcheck,omitempty"`
	inputFields  containerInputFields
}

type containerInputFields struct {
	privileged  bool
	capDrop     bool
	securityOpt bool
}

var containerFields = map[string]bool{
	"name": true, "image": true, "cvm_admin": true, "seal_register": true, "attestation": true, "command": true, "entrypoint": true,
	"working_dir": true, "user": true, "env": true, "secrets": true, "models": true, "keys": true,
	"volumes": true, "devices": true, "cap_add": true, "runtime": true,
	"networks": true, "ports": true, "ipc": true, "pid": true, "gpus": true,
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
