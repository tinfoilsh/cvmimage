package main

import "fmt"

const (
	maxConfigContainers       = 64
	maxConfigModels           = 64
	maxConfigNetworks         = 32
	maxConfigInboundPorts     = 64
	maxContainerListEntries   = 256
	maxContainerTmpfsEntries  = 64
	maxNetworkAllowEntries    = 256
	maxHealthcheckTestEntries = 64
	maxEnvironmentNameBytes   = 256
)

func validateConfigShape(config *Config) error {
	if len(config.Containers) > maxConfigContainers {
		return fmt.Errorf("containers exceeds limit %d", maxConfigContainers)
	}
	if len(config.Models) > maxConfigModels {
		return fmt.Errorf("models exceeds limit %d", maxConfigModels)
	}
	if len(config.Networks) > maxConfigNetworks {
		return fmt.Errorf("networks exceeds limit %d", maxConfigNetworks)
	}
	if len(config.CVMNetwork.InboundPorts) > maxConfigInboundPorts {
		return fmt.Errorf("cvm-network.inbound-ports exceeds limit %d", maxConfigInboundPorts)
	}
	for name, network := range config.Networks {
		if network != nil && len(network.Allow) > maxNetworkAllowEntries {
			return fmt.Errorf("networks.%s.allow exceeds limit %d", name, maxNetworkAllowEntries)
		}
	}
	for index := range config.Containers {
		if err := validateContainerShape(index, &config.Containers[index]); err != nil {
			return err
		}
	}
	return nil
}

func validateContainerShape(index int, container *Container) error {
	lists := []struct {
		name  string
		count int
	}{
		{name: "command", count: len(container.Command)},
		{name: "entrypoint", count: len(container.Entrypoint)},
		{name: "env", count: len(container.Env)},
		{name: "secrets", count: len(container.Secrets)},
		{name: "volumes", count: len(container.Volumes)},
		{name: "devices", count: len(container.Devices)},
		{name: "cap_add", count: len(container.CapAdd)},
		{name: "security_opt", count: len(container.SecurityOpt)},
		{name: "networks", count: len(container.Networks)},
	}
	for _, list := range lists {
		if list.count > maxContainerListEntries {
			return fmt.Errorf("containers[%d].%s exceeds limit %d", index, list.name, maxContainerListEntries)
		}
	}
	if len(container.Tmpfs) > maxContainerTmpfsEntries {
		return fmt.Errorf("containers[%d].tmpfs exceeds limit %d", index, maxContainerTmpfsEntries)
	}
	if container.Healthcheck != nil && len(container.Healthcheck.Test) > maxHealthcheckTestEntries {
		return fmt.Errorf("containers[%d].healthcheck.test exceeds limit %d", index, maxHealthcheckTestEntries)
	}
	for envIndex, item := range container.Env {
		switch value := item.(type) {
		case string:
			if !validEnvironmentName(value) {
				return fmt.Errorf("containers[%d].env[%d] has invalid environment name %q", index, envIndex, value)
			}
		case map[string]interface{}:
			if len(value) != 1 {
				return fmt.Errorf("containers[%d].env[%d] must contain exactly one key", index, envIndex)
			}
			for key, scalar := range value {
				if !validEnvironmentName(key) {
					return fmt.Errorf("containers[%d].env[%d] has invalid environment name %q", index, envIndex, key)
				}
				switch scalar.(type) {
				case string, bool, int, uint64, float64:
				default:
					return fmt.Errorf("containers[%d].env[%d].%s must be a scalar", index, envIndex, key)
				}
			}
		default:
			return fmt.Errorf("containers[%d].env[%d] must be a name or one-key mapping", index, envIndex)
		}
	}
	for secretIndex, secret := range container.Secrets {
		if !validEnvironmentName(secret) {
			return fmt.Errorf("containers[%d].secrets[%d] has invalid environment name %q", index, secretIndex, secret)
		}
	}
	return nil
}

func validEnvironmentName(name string) bool {
	if len(name) == 0 || len(name) > maxEnvironmentNameBytes {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' {
			continue
		}
		if index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
