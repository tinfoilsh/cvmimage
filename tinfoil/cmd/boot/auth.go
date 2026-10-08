package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/ecrregistry"
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

// dockerHubAuthKey is the key Docker clients use for Docker Hub credentials;
// a plain "docker.io" entry is never matched by docker/cli lookups.
const dockerHubAuthKey = "https://index.docker.io/v1/"

func dockerAuthKey(host string) string {
	if host == "docker.io" || host == "index.docker.io" {
		return dockerHubAuthKey
	}
	return host
}

// registryHost resolves the registry hostname for a REGISTRY_<KEY>_TOKEN
// secret. A REGISTRY_<KEY>_HOST secret carries the hostname verbatim, since
// a secret name cannot encode hyphens; otherwise the key itself is decoded
// with underscores as dots (GHCR_IO -> ghcr.io).
func registryHost(ext *shimconfig.ExternalConfig, hostPart string) string {
	if host := ext.GetSecret("REGISTRY_" + hostPart + "_HOST"); host != "" {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.ReplaceAll(hostPart, "_", "."))
}

// setupRegistryAuth configures Docker auth from external-config secrets.
// Supports:
//   - REGISTRY_<HOST>_USER/TOKEN (e.g., REGISTRY_GHCR_IO_TOKEN)
//   - REGISTRY_<KEY>_HOST naming the registry when the key cannot encode it
//   - GCLOUD_KEY/GCLOUD_REGISTRY (GCP service account for Artifact Registry)
func setupRegistryAuth(ext *shimconfig.ExternalConfig) error {
	if err := ecrregistry.Configure(filepath.Join(boot.DockerConfigDir, ecrregistry.ConfigFileName), ext.GetSecret(ecrregistry.SecretName)); err != nil {
		return err
	}
	if ext == nil || ext.Secrets == nil {
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
	// Sorted so that aliases mapping to one key (docker.io, index.docker.io)
	// resolve the same way on every boot.
	configured := make(map[string]string)
	for _, key := range slices.Sorted(maps.Keys(ext.Secrets)) {
		token := ext.Secrets[key]
		if !strings.HasPrefix(key, "REGISTRY_") || !strings.HasSuffix(key, "_TOKEN") {
			continue
		}
		// Extract host: REGISTRY_GHCR_IO_TOKEN -> GHCR_IO -> ghcr.io
		hostPart := strings.TrimSuffix(strings.TrimPrefix(key, "REGISTRY_"), "_TOKEN")
		host := registryHost(ext, hostPart)
		if host == "" || token == "" || !registryPattern.MatchString(host) {
			continue
		}
		authKey := dockerAuthKey(host)
		if prev, dup := configured[authKey]; dup {
			log.Printf("Warning: registry auth for %s ignored, %s already configured", host, prev)
			continue
		}
		configured[authKey] = host
		user := ext.Secrets["REGISTRY_"+hostPart+"_USER"]
		if user == "" {
			user = "token"
		}
		cfg.Auths[authKey] = DockerAuth{Auth: base64.StdEncoding.EncodeToString([]byte(user + ":" + token))}
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
		if err := os.WriteFile(boot.GCloudKeyPath, []byte(gcloudKey), 0600); err != nil {
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
