package boot

const (
	RamdiskDir = "/mnt/ramdisk"
	PublicDir  = RamdiskDir + "/public"
	PrivateDir = RamdiskDir + "/private"

	// Public — mounted read-only into containers as /tinfoil.
	ConfigPath      = PublicDir + "/config.yml"
	AttestationPath = PublicDir + "/attestation.json"
	MPKDir          = PublicDir + "/mpk"

	// Private — only accessible to boot and shim processes (mode 0700).
	// Holds CVM-level secrets and material that must never reach a container.
	TLSDir             = PrivateDir + "/tls"
	TLSCertPath        = TLSDir + "/cert.pem"
	TLSKeyPath         = TLSDir + "/key.pem"
	HPKEKeyPath        = PrivateDir + "/hpke_key.json"
	ShimConfigPath     = PrivateDir + "/shim.yml"
	ExternalConfigPath = PrivateDir + "/external-config.yml"
	DockerConfigDir    = PrivateDir + "/docker-config"
	DockerConfigPath   = DockerConfigDir + "/config.json"
	GCloudKeyPath      = PrivateDir + "/gcloud_key.json"
	CacheDir           = PrivateDir + "/tfshim-cache"
	StatePath          = PrivateDir + "/boot-state.json"

	// ShimListenPort is the public TLS port served by tinfoil-shim.
	ShimListenPort = 443

	// HTTPChallengePort is the plaintext-HTTP port served by tinfoil-boot
	// during cert-proxy + tls-challenge.
	HTTPChallengePort = 80
)
