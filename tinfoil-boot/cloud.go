package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

const (
	gcloudKeyPath = "/mnt/ramdisk/gcloud_key.json"
)

// setupCloudAuth configures cloud provider authentication from external config
func setupCloudAuth() error {
	extConfig, err := getExternalConfig()
	if err != nil {
		return fmt.Errorf("no external config: %w", err)
	}

	// Setup gcloud authentication if key is provided
	if extConfig.GcloudKey != "" && extConfig.GcloudKey != "null" {
		slog.Info("setting up GCloud authentication")

		// Write service account key
		if err := os.WriteFile(gcloudKeyPath, []byte(extConfig.GcloudKey), 0600); err != nil {
			return fmt.Errorf("writing gcloud key: %w", err)
		}

		// Activate service account
		cmd := exec.Command("gcloud", "auth", "activate-service-account", "--quiet", "--key-file", gcloudKeyPath)
		cmd.Env = append(os.Environ(), "CLOUDSDK_CONFIG=/mnt/ramdisk/gcloud")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("activating service account: %w", err)
		}

		// Configure Docker registry auth
		if extConfig.GcloudRegistry != "" {
			slog.Info("configuring Docker registry", "registry", extConfig.GcloudRegistry)
			cmd = exec.Command("gcloud", "auth", "configure-docker", "--quiet", extConfig.GcloudRegistry)
			cmd.Env = append(os.Environ(), "CLOUDSDK_CONFIG=/mnt/ramdisk/gcloud")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			if err := cmd.Run(); err != nil {
				return fmt.Errorf("configuring docker registry: %w", err)
			}
		}

		slog.Info("GCloud authentication configured")
	}

	return nil
}
