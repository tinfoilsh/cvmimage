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
	TLSDir             = PrivateDir + "/tls"
	TLSCertPath        = TLSDir + "/cert.pem"
	TLSKeyPath         = TLSDir + "/key.pem"
	HPKEKeyPath        = PrivateDir + "/hpke_key.json"
	ShimConfigPath     = PrivateDir + "/shim.yml"
	EgressConfigPath   = PrivateDir + "/egress.yml"
	ExternalConfigPath = PrivateDir + "/external-config.yml"
	DockerConfigDir    = PrivateDir + "/docker-config"
	DockerConfigPath   = DockerConfigDir + "/config.json"
	ModelKeyDir        = PrivateDir + "/model-keys"
	GCloudKeyPath      = PrivateDir + "/gcloud_key.json"
	CacheDir           = PrivateDir + "/tfshim-cache"
	StatePath          = PrivateDir + "/boot-state.json"
	EgressStatePath    = PrivateDir + "/egress-prev"

	// Tinfoil binaries baked into the measured rootfs. Shared so PID 1, the
	// initrd switch_root target, and boot's service invocations cannot drift.
	InitBinary            = "/usr/bin/tinfoil-init"
	BootBinary            = "/usr/bin/tinfoil-boot"
	ShimBinary            = "/usr/bin/tinfoil-shim"
	EgressBinary          = "/usr/bin/tinfoil-egress"
	ContainerStatusBinary = "/usr/bin/tinfoil-container-status"

	// ShimListenPort is the public TLS port served by tinfoil-shim.
	ShimListenPort = 443

	// HTTPChallengePort is the plaintext-HTTP port served by tinfoil-boot
	// during cert-proxy + tls-challenge.
	HTTPChallengePort = 80
)
