package boot

const (
	RamdiskDir = "/mnt/ramdisk"
	PublicDir  = RamdiskDir + "/public"
	PrivateDir = RamdiskDir + "/private"

	// Public — mounted read-only into containers as /tinfoil
	ConfigPath         = PublicDir + "/config.yml"
	ExternalConfigPath = PublicDir + "/external-config.yml"
	AttestationPath    = PublicDir + "/attestation.json"
	AttestationV3Path  = PublicDir + "/attestation-v3.json"
	MPKDir             = PublicDir + "/mpk"

	// Private — only accessible to boot and shim processes
	TLSDir           = PrivateDir + "/tls"
	TLSCertPath      = TLSDir + "/cert.pem"
	TLSKeyPath       = TLSDir + "/key.pem"
	HPKEKeyPath      = PrivateDir + "/hpke_key.json"
	ShimConfigPath   = PrivateDir + "/shim.yml"
	DockerConfigDir  = PrivateDir + "/docker-config"
	DockerConfigPath = DockerConfigDir + "/config.json"
	GCloudKeyPath    = PrivateDir + "/gcloud_key.json"
	GCloudConfigPath = PrivateDir + "/gcloud"
	CacheDir         = PrivateDir + "/tfshim-cache"
	StatePath        = PrivateDir + "/boot-state.json"
)
