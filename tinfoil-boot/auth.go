package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	dockerConfigDir    = "/mnt/ramdisk/docker-config"
	dockerConfigPath   = "/mnt/ramdisk/docker-config/config.json"
	gcloudKeyPath      = "/mnt/ramdisk/gcloud_key.json"
	authCommandTimeout = 60 * time.Second
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
//   - GCLOUD_KEY/GCLOUD_REGISTRY (or gcloud-key/gcloud-registry for backward compat)
func setupRegistryAuth() error {
	os.Setenv("DOCKER_CONFIG", dockerConfigDir)

	ext, err := getExternalConfig()
	if err != nil || ext.Secrets == nil {
		log.Println("No external config, skipping registry auth")
		return nil
	}

	cfg := DockerConfig{Auths: make(map[string]DockerAuth)}

	// Load existing config
	if data, _ := os.ReadFile(dockerConfigPath); len(data) > 0 {
		json.Unmarshal(data, &cfg)
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

	// GCloud auth via CLI (supports both formats)
	gcloudKey := getSecret(ext.Secrets, "GCLOUD_KEY", "gcloud-key")
	gcloudRegistry := getSecret(ext.Secrets, "GCLOUD_REGISTRY", "gcloud-registry")
	if gcloudKey != "" {
		if err := setupGCloudAuth(gcloudKey, gcloudRegistry); err != nil {
			log.Printf("Warning: gcloud auth failed: %v", err)
		}
	}

	// Write config
	if len(cfg.Auths) > 0 {
		if err := os.MkdirAll(dockerConfigDir, 0700); err != nil {
			return fmt.Errorf("creating docker config dir: %w", err)
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(dockerConfigPath, data, 0600); err != nil {
			return fmt.Errorf("writing docker config: %w", err)
		}
	}
	return nil
}

// getSecret returns the first non-empty value from the given keys
func getSecret(secrets map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := secrets[k]; v != "" && v != "null" {
			return v
		}
	}
	return ""
}

func setupGCloudAuth(key, registry string) error {
	if err := os.WriteFile(gcloudKeyPath, []byte(key), 0600); err != nil {
		return err
	}

	env := append(os.Environ(), "CLOUDSDK_CONFIG=/mnt/ramdisk/gcloud")

	if err := runCmd(env, "gcloud", "auth", "activate-service-account", "--quiet", "--key-file", gcloudKeyPath); err != nil {
		return err
	}

	if registry != "" && registryPattern.MatchString(registry) {
		return runCmd(env, "gcloud", "auth", "configure-docker", "--quiet", registry)
	}
	return nil
}

func runCmd(env []string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), authCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s timed out", name)
		}
		return err
	}
	return nil
}
