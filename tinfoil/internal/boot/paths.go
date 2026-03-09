package boot

const (
	RamdiskDir         = "/mnt/ramdisk"
	TLSDir             = RamdiskDir + "/tls"
	TLSCertPath        = TLSDir + "/cert.pem"
	TLSKeyPath         = TLSDir + "/key.pem"
	AttestationPath    = RamdiskDir + "/attestation.json"
	AttestationV3Path  = RamdiskDir + "/attestation-v3.json"
	HPKEKeyPath        = RamdiskDir + "/hpke_key.json"
	ConfigPath         = RamdiskDir + "/config.yml"
	ExternalConfigPath = RamdiskDir + "/external-config.yml"
	ShimConfigPath     = RamdiskDir + "/shim.yml"
	DockerConfigDir    = RamdiskDir + "/docker-config"
	DockerConfigPath   = DockerConfigDir + "/config.json"
	GCloudKeyPath      = RamdiskDir + "/gcloud_key.json"
	GCloudConfigPath   = RamdiskDir + "/gcloud"
	CacheDir           = RamdiskDir + "/tfshim-cache"
	MPKDir             = RamdiskDir + "/mpk"
	StatePath          = RamdiskDir + "/boot-state.json"
)
