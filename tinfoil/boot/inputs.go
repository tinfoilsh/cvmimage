package boot

import (
	"fmt"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/device"
	configdecode "tinfoil/internal/runtimeconfig"
)

type inputs struct {
	config         *runtimeconfig.Config
	external       *shimconfig.ExternalConfig
	configSource   []byte
	externalSource []byte
	workload       Workload
}

func loadInputs(options Options, spec Spec) (*inputs, error) {
	configPath, err := device.ConfigDisk()
	if err != nil {
		return nil, fmt.Errorf("finding config disk: %w", err)
	}
	loaded, err := loadMeasuredInputs(configPath, options, spec)
	if err != nil {
		return nil, err
	}
	externalPath, err := device.ExternalConfigDisk()
	if err != nil {
		return nil, fmt.Errorf("finding external config disk: %w", err)
	}
	loaded.external, loaded.externalSource, err = shimconfig.LoadExternal(externalPath)
	if err != nil {
		return nil, err
	}
	return loaded, nil
}

func loadMeasuredInputs(configPath string, options Options, spec Spec) (*inputs, error) {
	config, configSource, err := configdecode.LoadVerified(configPath, options.ConfigHash, options.Debug)
	if err != nil {
		return nil, err
	}
	workload, err := spec.Configure(config)
	if err != nil {
		return nil, err
	}
	if workload.DeviceEvidence == nil {
		return nil, fmt.Errorf("device evidence provider is required")
	}
	return &inputs{config: config, configSource: configSource, workload: workload}, nil
}
