package bootstate

const (
	RamdiskDir = "/mnt/ramdisk"
	PublicDir  = RamdiskDir + "/public"
	PrivateDir = RamdiskDir + "/private"

	// Public boot artifacts.
	ConfigPath      = PublicDir + "/config.yml"
	AttestationPath = PublicDir + "/attestation.json"

	PublicModelsDir = PublicDir + "/models"
	MWPDir          = PublicDir + "/mwp"
	MPKDir          = PublicDir + "/mpk" // Legacy alias directory for MWP mounts.

	// Private boot artifacts, stored beneath a mode 0700 directory.
	TLSDir                = PrivateDir + "/tls"
	TLSCertPath           = TLSDir + "/cert.pem"
	TLSKeyPath            = TLSDir + "/key.pem"
	HPKEKeyPath           = PrivateDir + "/hpke_key.json"
	CollateralRequestPath = PrivateDir + "/collateral-request.json"
	ShimConfigPath        = PrivateDir + "/shim.yml"

	ExternalConfigPath = PrivateDir + "/external-config.yml"
	PrivateModelsDir   = PrivateDir + "/models"
	RuntimeConfigPath  = PrivateDir + "/runtime-config.yml"

	CacheDir  = PrivateDir + "/tfshim-cache"
	StatePath = PrivateDir + "/boot-state.json"

	ShimPIDPath = "/run/tinfoil/pids/tinfoil-shim.pid"

	// ShimListenPort is the public TLS port served by tinfoil-shim.
	ShimListenPort = 443

	// HTTPChallengePort is the plaintext-HTTP port served by tinfoil-boot
	// during cert-proxy + tls-challenge.
	HTTPChallengePort = 80

	// InitBinary is PID 1 after the measured root replaces the initrd.
	InitBinary = "/usr/bin/tinfoil-pid1"
	BootBinary = "/usr/bin/tinfoil-boot"

	ShimBinary = "/usr/bin/tinfoil-shim"

	// ExternalNICPCIAddress is the measured virtio-net topology ABI. It MUST
	// match tinfoild/admin/guest_topology.go.
	ExternalNICPCIAddress = "0000:00:02.0"
)
