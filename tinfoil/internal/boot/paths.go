package boot

const (
	RamdiskDir = "/mnt/ramdisk"
	PublicDir  = RamdiskDir + "/public"
	PrivateDir = RamdiskDir + "/private"

	// Public — mounted read-only into containers as /tinfoil.
	ConfigPath          = PublicDir + "/config.yml"
	AttestationPath     = PublicDir + "/attestation.json"
	ContainerStatusPath = PublicDir + "/container-status.json"
	MWPDir              = PublicDir + "/mwp"
	MPKDir              = PublicDir + "/mpk" // Legacy alias directory for MWP mounts.

	// Private — only accessible to boot, egress, and shim processes (mode 0700).
	// Holds CVM-level secrets and material that must never reach a container.
	TLSDir                  = PrivateDir + "/tls"
	TLSCertPath             = TLSDir + "/cert.pem"
	TLSKeyPath              = TLSDir + "/key.pem"
	HPKEKeyPath             = PrivateDir + "/hpke_key.json"
	AttestationMaterialPath = PrivateDir + "/attestation-material.json"
	ShimConfigPath          = PrivateDir + "/shim.yml"
	EgressConfigPath        = PrivateDir + "/egress.yml"
	ExternalConfigPath      = PrivateDir + "/external-config.yml"
	RuntimeConfigPath       = PrivateDir + "/runtime-config.yml"
	RuntimeBootedPath       = PrivateDir + "/runtime-booted"
	DockerConfigDir         = PrivateDir + "/docker-config"
	DockerConfigPath        = DockerConfigDir + "/config.json"
	GCloudKeyPath           = PrivateDir + "/gcloud_key.json"
	CacheDir                = PrivateDir + "/tfshim-cache"
	StatePath               = PrivateDir + "/boot-state.json"
	EgressStatePath         = PrivateDir + "/egress-prev"

	// NVIDIABootstrapStatusPath is the fixed PID 1 to tinfoil-boot handoff
	// for NVIDIA bring-up readiness.
	NVIDIABootstrapStatusPath = "/run/tinfoil/nvidia-bootstrap-status"
	ContainersReadyPath       = "/run/tinfoil/containers.ready"
	ShimPIDPath               = "/run/tinfoil/pids/tinfoil-shim.pid"
	EgressPIDPath             = "/run/tinfoil/pids/tinfoil-egress.pid"

	// ShimListenPort is the public TLS port served by tinfoil-shim.
	ShimListenPort = 443

	// HTTPChallengePort is the plaintext-HTTP port served by tinfoil-boot
	// during cert-proxy + tls-challenge.
	HTTPChallengePort = 80

	// InitBinary is PID 1 after the measured root replaces the initrd.
	InitBinary       = "/usr/bin/tinfoil-pid1"
	BootBinary       = "/usr/bin/tinfoil-boot"
	ContainersBinary = "/usr/bin/tinfoil-containers"
	ContainersSocket = "/run/tinfoil/containers.sock"
	EgressBinary     = "/usr/bin/tinfoil-egress"
	ShimBinary       = "/usr/bin/tinfoil-shim"

	// ExternalNICPCIAddress is the measured virtio-net topology ABI. It MUST
	// match tinfoild/admin/guest_topology.go.
	ExternalNICPCIAddress = "0000:00:02.0"
)
