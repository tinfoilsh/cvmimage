package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/docker/docker/api/types/registry"
	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

const (
	secretGCloudKey      = "GCLOUD_KEY"
	secretGCloudRegistry = "GCLOUD_REGISTRY"

	maxDockerConfigBytes      = 1 << 20
	maxDockerRegistries       = 1024
	maxDockerRegistryKeyBytes = 256
	maxDecodedCredentialBytes = 128<<10 + 1
)

type DockerConfig struct {
	Auths map[string]DockerAuth `json:"auths"`
}

type DockerAuth struct {
	Auth string `json:"auth"`
}

func loadDockerConfig(path string) (DockerConfig, error) {
	data, err := readDockerConfigFile(path)
	if err != nil {
		return DockerConfig{}, err
	}
	return parseDockerConfig(data)
}

func readDockerConfigFile(path string) ([]byte, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		unix.Close(descriptor)
		return nil, fmt.Errorf("opening docker config descriptor")
	}
	defer file.Close()

	var initial unix.Stat_t
	if err := unix.Fstat(descriptor, &initial); err != nil {
		return nil, err
	}
	if initial.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("docker config is not a regular file")
	}
	if initial.Mode&0077 != 0 {
		return nil, fmt.Errorf("docker config permissions %#o expose credentials", initial.Mode&0777)
	}
	if initial.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("docker config owner %d does not match effective user %d", initial.Uid, os.Geteuid())
	}
	if initial.Size > maxDockerConfigBytes {
		return nil, fmt.Errorf("docker config exceeds %d-byte limit", maxDockerConfigBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxDockerConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDockerConfigBytes {
		return nil, fmt.Errorf("docker config exceeds %d-byte limit", maxDockerConfigBytes)
	}

	var final unix.Stat_t
	if err := unix.Fstat(descriptor, &final); err != nil {
		return nil, err
	}
	if initial.Size != final.Size ||
		initial.Mtim.Sec != final.Mtim.Sec || initial.Mtim.Nsec != final.Mtim.Nsec ||
		initial.Ctim.Sec != final.Ctim.Sec || initial.Ctim.Nsec != final.Ctim.Nsec {
		return nil, fmt.Errorf("docker config changed while being read")
	}
	return data, nil
}

func parseDockerConfig(data []byte) (DockerConfig, error) {
	if len(data) > maxDockerConfigBytes {
		return DockerConfig{}, fmt.Errorf("docker config exceeds %d-byte limit", maxDockerConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return DockerConfig{}, fmt.Errorf("docker config: %w", err)
	}
	if !decoder.More() {
		return DockerConfig{}, fmt.Errorf("docker config: missing auths")
	}
	key, err := decodeJSONString(decoder)
	if err != nil {
		return DockerConfig{}, fmt.Errorf("docker config: %w", err)
	}
	if key != "auths" {
		return DockerConfig{}, fmt.Errorf("docker config: unknown field %q", key)
	}
	auths, err := decodeDockerAuths(decoder)
	if err != nil {
		return DockerConfig{}, fmt.Errorf("docker config auths: %w", err)
	}
	if decoder.More() {
		key, err := decodeJSONString(decoder)
		if err != nil {
			return DockerConfig{}, fmt.Errorf("docker config: %w", err)
		}
		return DockerConfig{}, fmt.Errorf("docker config: unknown or duplicate field %q", key)
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return DockerConfig{}, fmt.Errorf("docker config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return DockerConfig{}, fmt.Errorf("docker config: %w", err)
	}
	return DockerConfig{Auths: auths}, nil
}

func decodeDockerAuths(decoder *json.Decoder) (map[string]DockerAuth, error) {
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	auths := make(map[string]DockerAuth)
	for decoder.More() {
		if len(auths) >= maxDockerRegistries {
			return nil, fmt.Errorf("registry count exceeds %d", maxDockerRegistries)
		}
		registryKey, err := decodeJSONString(decoder)
		if err != nil {
			return nil, err
		}
		if registryKey == "" || len(registryKey) > maxDockerRegistryKeyBytes {
			return nil, fmt.Errorf("invalid registry key length %d", len(registryKey))
		}
		if _, exists := auths[registryKey]; exists {
			return nil, fmt.Errorf("duplicate registry %q", registryKey)
		}
		auth, err := decodeDockerAuth(decoder)
		if err != nil {
			return nil, fmt.Errorf("registry %q: %w", registryKey, err)
		}
		auths[registryKey] = auth
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return nil, err
	}
	return auths, nil
}

func decodeDockerAuth(decoder *json.Decoder) (DockerAuth, error) {
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return DockerAuth{}, err
	}
	if !decoder.More() {
		return DockerAuth{}, fmt.Errorf("missing auth")
	}
	key, err := decodeJSONString(decoder)
	if err != nil {
		return DockerAuth{}, err
	}
	if key != "auth" {
		return DockerAuth{}, fmt.Errorf("unknown field %q", key)
	}
	var encoded string
	if err := decoder.Decode(&encoded); err != nil {
		return DockerAuth{}, fmt.Errorf("auth must be a string: %w", err)
	}
	if err := validateDockerCredential(encoded); err != nil {
		return DockerAuth{}, err
	}
	if decoder.More() {
		key, err := decodeJSONString(decoder)
		if err != nil {
			return DockerAuth{}, err
		}
		return DockerAuth{}, fmt.Errorf("unknown or duplicate field %q", key)
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return DockerAuth{}, err
	}
	return DockerAuth{Auth: encoded}, nil
}

func validateDockerCredential(encoded string) error {
	if encoded == "" {
		return fmt.Errorf("missing auth")
	}
	if base64.StdEncoding.DecodedLen(len(encoded)) > maxDecodedCredentialBytes+2 {
		return fmt.Errorf("decoded credential exceeds %d-byte limit", maxDecodedCredentialBytes)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("invalid auth base64: %w", err)
	}
	if len(decoded) > maxDecodedCredentialBytes {
		return fmt.Errorf("decoded credential exceeds %d-byte limit", maxDecodedCredentialBytes)
	}
	username, password, found := bytes.Cut(decoded, []byte{':'})
	if !found || len(username) == 0 || len(password) == 0 || bytes.IndexByte(decoded, 0) >= 0 {
		return fmt.Errorf("missing username or password")
	}
	return nil
}

func decodeJSONString(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", fmt.Errorf("expected string key")
	}
	return value, nil
}

func expectJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return fmt.Errorf("expected %q", expected)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing data")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

func registryAuthForImage(path, imageName string) (string, error) {
	config, err := loadDockerConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("loading docker auth: %w", err)
	}

	host := imageRegistryHost(imageName)
	auth, registryKey, found := dockerAuthForHost(config.Auths, host)
	if !found {
		return "", nil
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(auth.Auth)
	if err != nil {
		return "", fmt.Errorf("decoding docker auth for %q: %w", registryKey, err)
	}
	username, password, found := strings.Cut(string(decoded), ":")
	if !found || username == "" || password == "" {
		return "", fmt.Errorf("invalid docker auth for %q", registryKey)
	}
	return registry.EncodeAuthConfig(registry.AuthConfig{
		Username:      username,
		Password:      password,
		ServerAddress: registryKey,
	})
}

func imageRegistryHost(imageName string) string {
	host := "docker.io"
	if parts := strings.Split(imageName, "/"); len(parts) > 1 && strings.Contains(parts[0], ".") {
		host = parts[0]
	}
	return host
}

func dockerAuthForHost(auths map[string]DockerAuth, host string) (DockerAuth, string, bool) {
	if auth, found := auths[host]; found {
		return auth, host, true
	}
	for registryKey, auth := range auths {
		if normalizeRegistryHost(registryKey) == host {
			return auth, registryKey, true
		}
	}
	return DockerAuth{}, "", false
}

func normalizeRegistryHost(registryKey string) string {
	if strings.Contains(registryKey, "://") {
		parsed, err := url.Parse(registryKey)
		if err == nil && parsed.Hostname() != "" {
			if parsed.Port() == "" {
				return parsed.Hostname()
			}
			return net.JoinHostPort(parsed.Hostname(), parsed.Port())
		}
	}
	host, _, _ := strings.Cut(registryKey, "/")
	return host
}

func setDockerAuth(config *DockerConfig, registryKey, encoded string) error {
	if registryKey == "" || len(registryKey) > maxDockerRegistryKeyBytes {
		return fmt.Errorf("invalid registry key length %d", len(registryKey))
	}
	if err := validateDockerCredential(encoded); err != nil {
		return fmt.Errorf("registry %q: %w", registryKey, err)
	}
	if _, exists := config.Auths[registryKey]; !exists && len(config.Auths) >= maxDockerRegistries {
		return fmt.Errorf("docker registry count exceeds %d", maxDockerRegistries)
	}
	config.Auths[registryKey] = DockerAuth{Auth: encoded}
	return nil
}

// setupRegistryAuth configures Docker auth from external-config secrets.
// Supports:
//   - REGISTRY_<HOST>_USER/TOKEN (e.g., REGISTRY_GHCR_IO_TOKEN)
//   - GCLOUD_KEY/GCLOUD_REGISTRY (GCP service account for Artifact Registry)
func setupRegistryAuth(ext *shimconfig.ExternalConfig) error {
	os.Setenv("DOCKER_CONFIG", boot.DockerConfigDir)
	if ext == nil || ext.Secrets == nil {
		log.Println("No external config, skipping registry auth")
		return nil
	}

	cfg, err := loadDockerConfig(boot.DockerConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		cfg = DockerConfig{Auths: make(map[string]DockerAuth)}
	} else if err != nil {
		return fmt.Errorf("loading existing docker config: %w", err)
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
		if host == "" || token == "" || !isRegistry(host) {
			continue
		}
		user := ext.Secrets["REGISTRY_"+hostPart+"_USER"]
		if user == "" {
			user = "token"
		}
		if err := setDockerAuth(&cfg, host, base64.StdEncoding.EncodeToString([]byte(user+":"+token))); err != nil {
			return err
		}
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
			if reg != "" && isRegistry(reg) {
				encoded := base64.StdEncoding.EncodeToString([]byte("_json_key_base64:" + base64.StdEncoding.EncodeToString([]byte(gcloudKey))))
				if err := setDockerAuth(&cfg, reg, encoded); err != nil {
					return err
				}
				log.Printf("Auth configured: %s (GCP service account)", reg)
			}
		}
	}

	// Write config
	if len(cfg.Auths) > 0 {
		if len(cfg.Auths) > maxDockerRegistries {
			return fmt.Errorf("docker registry count exceeds %d", maxDockerRegistries)
		}
		if err := os.MkdirAll(boot.DockerConfigDir, 0700); err != nil {
			return fmt.Errorf("creating docker config dir: %w", err)
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding docker config: %w", err)
		}
		if len(data) > maxDockerConfigBytes {
			return fmt.Errorf("docker config exceeds %d-byte limit", maxDockerConfigBytes)
		}
		if err := os.WriteFile(boot.DockerConfigPath, data, 0600); err != nil {
			return fmt.Errorf("writing docker config: %w", err)
		}
	}
	return nil
}
