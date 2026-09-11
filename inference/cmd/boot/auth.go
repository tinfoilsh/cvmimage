package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"tinfoil/inference/internal/variant"
	"tinfoil/internal/secretstore"
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

// setupRegistryAuth configures Docker auth from the supplied credentials.
// Supports:
//   - REGISTRY_<HOST>_USER/TOKEN (e.g., REGISTRY_GHCR_IO_TOKEN)
//   - GCLOUD_KEY/GCLOUD_REGISTRY (GCP service account for Artifact Registry)
func setupRegistryAuth(credentials secretstore.Store) error {
	os.Setenv("DOCKER_CONFIG", variant.DockerConfigDir)
	return writeRegistryAuth(credentials, variant.DockerConfigPath, variant.GCloudKeyPath)
}

func writeRegistryAuth(credentials secretstore.Store, configPath, gcloudKeyPath string) error {
	if credentials == nil {
		log.Println("No external config, skipping registry auth")
		return nil
	}

	cfg := DockerConfig{Auths: make(map[string]DockerAuth)}

	if data, err := os.ReadFile(configPath); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Printf("Warning: failed to parse existing docker config: %v", err)
		}
		if cfg.Auths == nil {
			cfg.Auths = make(map[string]DockerAuth)
		}
	}

	// Generic registry auth: REGISTRY_<HOST>_TOKEN (user optional)
	// Host format: underscores become dots (GHCR_IO -> ghcr.io)
	for key, token := range credentials {
		if !strings.HasPrefix(key, "REGISTRY_") || !strings.HasSuffix(key, "_TOKEN") {
			continue
		}
		// Extract host: REGISTRY_GHCR_IO_TOKEN -> GHCR_IO -> ghcr.io
		hostPart := strings.TrimSuffix(strings.TrimPrefix(key, "REGISTRY_"), "_TOKEN")
		host := strings.ToLower(strings.ReplaceAll(hostPart, "_", "."))
		if host == "" || token == "" || !registryPattern.MatchString(host) {
			continue
		}
		user := credentials["REGISTRY_"+hostPart+"_USER"]
		if user == "" {
			user = "token"
		}
		cfg.Auths[host] = DockerAuth{Auth: base64.StdEncoding.EncodeToString([]byte(user + ":" + token))}
		log.Printf("Auth configured: %s", host)
	}

	// GCP Artifact Registry auth via service account JSON key
	gcloudKey := credentials.GetSecret(secretGCloudKey)
	if gcloudKey == "" {
		gcloudKey = credentials.GetSecret("gcloud-key")
	}
	gcloudRegistry := credentials.GetSecret(secretGCloudRegistry)
	if gcloudRegistry == "" {
		gcloudRegistry = credentials.GetSecret("gcloud-registry")
	}
	if gcloudKey != "" {
		// Write key file for containers that mount it directly (e.g., Pollux)
		if err := os.WriteFile(gcloudKeyPath, []byte(gcloudKey), 0600); err != nil {
			log.Printf("Warning: failed to write GCloud key file: %v", err)
		}
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
		if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
			return fmt.Errorf("creating docker config dir: %w", err)
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			return fmt.Errorf("writing docker config: %w", err)
		}
	}
	return nil
}

var registryPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
