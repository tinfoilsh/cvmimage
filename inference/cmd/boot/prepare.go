package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"time"

	"tinfoil/inference/internal/variant"
	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/modelpack"
	"tinfoil/internal/secretstore"
)

func prepareWorkload(tracker *bootstate.Tracker, mounts []modelpack.Mount, external *shimconfig.ExternalConfig, resolved secretstore.Store) error {
	start := time.Now()
	if err := setupRegistryAuth(registryCredentials(external, resolved)); err != nil {
		tracker.Record(variant.StageRegistryAuth, bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("registry auth setup failed: %w", err)
	}
	tracker.Record(variant.StageRegistryAuth, bootstate.StatusOK, time.Since(start), "")

	if err := prepareModelDirectories(mounts, bootstate.PublicModelsDir); err != nil {
		tracker.Record(bootstate.StageModels, bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	return nil
}

// Containers bind isolated models over these empty public mount points.
func prepareModelDirectories(mounts []modelpack.Mount, directory string) error {
	for _, mount := range mounts {
		if mount.LegacyAlias {
			continue
		}
		if err := os.MkdirAll(filepath.Join(directory, mount.Model.Name), 0755); err != nil {
			return fmt.Errorf("creating container mount point for model %q: %w", mount.Model.Name, err)
		}
	}
	return nil
}

// Registry credentials may be host inputs or declared workload secrets.
func registryCredentials(external *shimconfig.ExternalConfig, resolved secretstore.Store) secretstore.Store {
	credentials := make(secretstore.Store)
	if external != nil {
		maps.Copy(credentials, external.Secrets)
	}
	maps.Copy(credentials, resolved)
	return credentials
}
