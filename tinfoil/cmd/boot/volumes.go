package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/volume"
)

func mountVolumes(ctx context.Context, config *Config, external *shimconfig.ExternalConfig, mount func(context.Context, volume.Spec, []byte) error) error {
	for index, spec := range config.Volumes {
		if spec.KeySecret == "" {
			continue
		}
		key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(external.GetSecret(spec.KeySecret)))
		if err != nil || len(key) != volume.KeyBytes {
			clear(key)
			return fmt.Errorf("volume %s key %s is not base64 for %d bytes", spec.Name, spec.KeySecret, volume.KeyBytes)
		}
		err = mount(ctx, volume.Spec{VolumeSpec: spec, Models: len(config.Models), Index: index}, key)
		clear(key)
		if err != nil {
			return fmt.Errorf("opening volume %s: %w", spec.Name, err)
		}
	}
	return nil
}
