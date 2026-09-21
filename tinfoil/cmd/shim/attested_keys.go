package main

import (
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"gopkg.in/yaml.v3"
	"tinfoil/internal/attestedkeys"
	"tinfoil/internal/runtimeconfig"
)

func loadWorkloadKeys(configPath, storePath string) ([]envelope.CryptoMaterialItem, error) {
	// Boot writes these exact measured bytes before generating the inventory.
	// They are available before the later runtime/container config handoff.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config runtimeconfig.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	// Boot already validated the full production/debug profile. LoadPublic
	// revalidates declarations and matches all grants to the completed store.
	return attestedkeys.LoadPublic(storePath, &config)
}
