package main

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

const shimConfigPath = "/mnt/ramdisk/shim.yml"

func writeShimConfig(config *Config) error {
	shimConfigData, err := yaml.Marshal(config.Shim)
	if err != nil {
		return fmt.Errorf("marshaling shim config: %w", err)
	}

	if err := os.WriteFile(shimConfigPath, shimConfigData, 0644); err != nil {
		return fmt.Errorf("writing shim config: %w", err)
	}

	log.Println("Shim config written, systemd will auto-start tinfoil-shim.service")
	return nil
}
