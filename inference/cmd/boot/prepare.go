package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"
	"tinfoil/boot"
	"tinfoil/inference/internal/variant"
	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
)

func prepareWorkload(tracker *bootstate.Tracker, config *boot.Config, external *shimconfig.ExternalConfig) error {
	start := time.Now()
	if err := setupRegistryAuth(external); err != nil {
		tracker.Record(variant.StageRegistryAuth, bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("registry auth setup failed: %w", err)
	}
	tracker.Record(variant.StageRegistryAuth, bootstate.StatusOK, time.Since(start), "")

	if err := prepareModelDirectories(config, bootstate.PublicModelsDir); err != nil {
		tracker.Record(bootstate.StageModels, bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	return nil
}

// Containers bind isolated models over these empty public mount points.
func prepareModelDirectories(config *boot.Config, directory string) error {
	for _, model := range config.Models {
		if !runtimeconfig.ModelIsIsolated(config, model.Name) {
			continue
		}
		if err := os.MkdirAll(filepath.Join(directory, model.Name), 0755); err != nil {
			return fmt.Errorf("creating container mount point for model %q: %w", model.Name, err)
		}
	}
	return nil
}
