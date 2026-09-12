package boot

import (
	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/attestation"
	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/secretstore"
	"tinfoil/internal/volume"
)

// Spec declares the boot stages and compiles workload policy from verified config.
type Spec struct {
	Stages    []string
	Configure func(*runtimeconfig.Config) (Workload, error)
}

// Workload declares resources once, before provisioning begins.
// Hooks run at the fixed device-attestation and workload-preparation phases.
type Workload struct {
	Volumes        volume.Plan
	Secrets        []string
	DeviceEvidence attestation.DeviceEvidenceProvider
	AttestDevices  func(*bootstate.Tracker) error
	Prepare        func(*bootstate.Tracker, *shimconfig.ExternalConfig, secretstore.Store) error
}

// Options contains the measured boot inputs and inherited secret descriptor.
type Options struct {
	ConfigHash string
	Debug      bool
	SecretsFD  int
	StorageFD  int
}
