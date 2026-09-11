package variant

import "tinfoil/internal/bootstate"

const (
	RuntimeConfigPath         = bootstate.PrivateDir + "/runtime-config.yml"
	ContainerStatusPath       = bootstate.PublicDir + "/container-status.json"
	ContainerModelsDir        = "/tinfoil/models"
	EgressConfigPath          = bootstate.PrivateDir + "/egress.yml"
	RuntimeBootedPath         = bootstate.PrivateDir + "/runtime-booted"
	DockerConfigDir           = bootstate.PrivateDir + "/docker-config"
	DockerConfigPath          = DockerConfigDir + "/config.json"
	GCloudKeyPath             = bootstate.PrivateDir + "/gcloud_key.json"
	EgressStatePath           = bootstate.PrivateDir + "/egress-prev"
	NVIDIABootstrapStatusPath = "/run/tinfoil/nvidia-bootstrap-status"
	ContainersReadyPath       = "/run/tinfoil/containers.ready"
	EgressPIDPath             = "/run/tinfoil/pids/tinfoil-egress.pid"
	ContainersBinary          = "/usr/bin/tinfoil-containers"
	ContainersSocket          = "/run/tinfoil/containers.sock"
	EgressBinary              = "/usr/bin/tinfoil-egress"
	StageGPUAttestation       = "gpu-attestation"
	StageFirewall             = "firewall"
	StageContainers           = "containers"
)
