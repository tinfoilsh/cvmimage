package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

const (
	gcloudKeyPath = "/mnt/ramdisk/gcloud_key.json"

	// Secret keys for GCloud authentication in external-config.yml
	secretKeyGCloudKey      = "gcloud-key"
	secretKeyGCloudRegistry = "gcloud-registry"
)

// setupCloudAuth configures cloud provider authentication from external config
func setupCloudAuth() error {
	extConfig, err := getExternalConfig()
	if err != nil {
		return fmt.Errorf("no external config: %w", err)
	}

	// gcloud-key is a secret
	gcloudKey := ""
	if extConfig.Secrets != nil {
		gcloudKey = extConfig.Secrets[secretKeyGCloudKey]
	}
	if gcloudKey == "" || gcloudKey == "null" {
		return nil
	}

	slog.Info("setting up GCloud authentication")

	if err := os.WriteFile(gcloudKeyPath, []byte(gcloudKey), 0600); err != nil {
		return fmt.Errorf("writing gcloud key: %w", err)
	}

	// Activate service account
	cmd := exec.Command("gcloud", "auth", "activate-service-account", "--quiet", "--key-file", gcloudKeyPath)
	cmd.Env = append(os.Environ(), "CLOUDSDK_CONFIG=/mnt/ramdisk/gcloud")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("activating service account: %w", err)
	}

	// Configure Docker registry auth (gcloud-registry is also in secrets)
	registry := ""
	if extConfig.Secrets != nil {
		registry = extConfig.Secrets[secretKeyGCloudRegistry]
	}
	if registry != "" {
		if !registryPattern.MatchString(registry) {
			return fmt.Errorf("invalid registry format: %s", registry)
		}
		slog.Info("configuring Docker registry", "registry", registry)
		cmd = exec.Command("gcloud", "auth", "configure-docker", "--quiet", registry)
		cmd.Env = append(os.Environ(), "CLOUDSDK_CONFIG=/mnt/ramdisk/gcloud")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("configuring docker registry: %w", err)
		}
	}

	slog.Info("GCloud authentication configured")
	return nil
}
