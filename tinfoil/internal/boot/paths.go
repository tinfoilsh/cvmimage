package boot

const (
	RamdiskDir = "/mnt/ramdisk"

	// RamdiskPrivateDir holds enclave secrets and daemon state. It is created
	// 0700 and is never mounted into workload containers.
	RamdiskPrivateDir = RamdiskDir + "/private"

	// RamdiskPublicDir holds data that workload containers may read (model
	// packs). It is bind-mounted read-only into containers at /tinfoil.
	RamdiskPublicDir = RamdiskDir + "/public"

	TLSDir             = RamdiskPrivateDir + "/tls"
	TLSCertPath        = TLSDir + "/cert.pem"
	TLSKeyPath         = TLSDir + "/key.pem"
	AttestationPath    = RamdiskPrivateDir + "/attestation.json"
	HPKEKeyPath        = RamdiskPrivateDir + "/hpke_key.json"
	ConfigPath         = RamdiskPrivateDir + "/config.yml"
	ExternalConfigPath = RamdiskPrivateDir + "/external-config.yml"
	ShimConfigPath     = RamdiskPrivateDir + "/shim.yml"
	DockerConfigDir    = RamdiskPrivateDir + "/docker-config"
	DockerConfigPath   = DockerConfigDir + "/config.json"
	GCloudKeyPath      = RamdiskPrivateDir + "/gcloud_key.json"
	CacheDir           = RamdiskPrivateDir + "/tfshim-cache"
	StatePath          = RamdiskPrivateDir + "/boot-state.json"

	MPKDir = RamdiskPublicDir + "/mpk"
)
