package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"tinfoil/internal/boot"
)

const (
	secretGCloudKey      = "GCLOUD_KEY"
	secretGCloudRegistry = "GCLOUD_REGISTRY"
)

type DockerConfig struct {
	Auths map[string]DockerAuth `json:"auths"`
}

type DockerAuth struct {
	Auth string `json:"auth"`
}

// setupRegistryAuth configures Docker auth from external-config secrets.
// Supports:
//   - REGISTRY_<HOST>_USER/TOKEN (e.g., REGISTRY_GHCR_IO_TOKEN)
//   - GCLOUD_KEY/GCLOUD_REGISTRY (GCP service account for Artifact Registry)
func setupRegistryAuth() error {
	os.Setenv("DOCKER_CONFIG", boot.DockerConfigDir)

	ext, err := getExternalConfig()
	if err != nil || ext.Secrets == nil {
		log.Println("No external config, skipping registry auth")
		return nil
	}

	cfg := DockerConfig{Auths: make(map[string]DockerAuth)}

	if data, err := os.ReadFile(boot.DockerConfigPath); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Printf("Warning: failed to parse existing docker config: %v", err)
		}
		if cfg.Auths == nil {
			cfg.Auths = make(map[string]DockerAuth)
		}
	}

	// Generic registry auth: REGISTRY_<HOST>_TOKEN (user optional)
	// Host format: underscores become dots (GHCR_IO -> ghcr.io)
	for key, token := range ext.Secrets {
		if !strings.HasPrefix(key, "REGISTRY_") || !strings.HasSuffix(key, "_TOKEN") {
			continue
		}
		// Extract host: REGISTRY_GHCR_IO_TOKEN -> GHCR_IO -> ghcr.io
		hostPart := strings.TrimSuffix(strings.TrimPrefix(key, "REGISTRY_"), "_TOKEN")
		host := strings.ToLower(strings.ReplaceAll(hostPart, "_", "."))
		if host == "" || token == "" || !registryPattern.MatchString(host) {
			continue
		}
		user := ext.Secrets["REGISTRY_"+hostPart+"_USER"]
		if user == "" {
			user = "token"
		}
		cfg.Auths[host] = DockerAuth{Auth: base64.StdEncoding.EncodeToString([]byte(user + ":" + token))}
		log.Printf("Auth configured: %s", host)
	}

	// GCP Artifact Registry auth via service account JSON key
	gcloudKey := ext.GetSecret(secretGCloudKey)
	if gcloudKey == "" {
		gcloudKey = ext.GetSecret("gcloud-key")
	}
	gcloudRegistry := ext.GetSecret(secretGCloudRegistry)
	if gcloudRegistry == "" {
		gcloudRegistry = ext.GetSecret("gcloud-registry")
	}
	if gcloudKey != "" {
		// Write key file for containers that mount it directly (e.g., Pollux)
		os.WriteFile(boot.GCloudKeyPath, []byte(gcloudKey), 0600)
	}
	if gcloudKey != "" && gcloudRegistry != "" {
		registries := strings.Split(gcloudRegistry, ",")
		for _, reg := range registries {
			reg = strings.TrimSpace(reg)
			if reg != "" && registryPattern.MatchString(reg) {
				cfg.Auths[reg] = DockerAuth{
					Auth: base64.StdEncoding.EncodeToString([]byte("_json_key_base64:" + base64.StdEncoding.EncodeToString([]byte(gcloudKey)))),
				}
				log.Printf("Auth configured: %s (GCP service account)", reg)
			}
		}
	}

	// Write config
	if len(cfg.Auths) > 0 {
		if err := os.MkdirAll(boot.DockerConfigDir, 0700); err != nil {
			return fmt.Errorf("creating docker config dir: %w", err)
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(boot.DockerConfigPath, data, 0600); err != nil {
			return fmt.Errorf("writing docker config: %w", err)
		}
	}
	return nil
}

