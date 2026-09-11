package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/modelpack"
	"tinfoil/internal/secretstore"
)

func TestRegistryAuthUsesProvidedSecrets(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "docker", "config.json")
	keyPath := filepath.Join(directory, "gcloud.json")
	provided := &shimconfig.ExternalConfig{Secrets: map[string]string{
		"REGISTRY_GHCR_IO_USER":  "inference",
		"REGISTRY_GHCR_IO_TOKEN": "resolved-token",
		"GCLOUD_KEY":             "resolved-gcloud-key",
		"GCLOUD_REGISTRY":        "us-docker.pkg.dev",
	}}
	if err := writeRegistryAuth(secretstore.Store(provided.Secrets), configPath, keyPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var config DockerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("inference:resolved-token"))
	if config.Auths["ghcr.io"].Auth != want || config.Auths["us-docker.pkg.dev"].Auth == "" {
		t.Fatalf("registry config = %#v", config)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil || string(key) != "resolved-gcloud-key" {
		t.Fatalf("gcloud key = %q, error = %v", key, err)
	}
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("registry config permissions: %v, %v", info, err)
	}
}

func TestPrepareModelDirectoriesOnlyCreatesGrantedMountPoints(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "models")
	mounts := []modelpack.Mount{
		{Model: runtimeconfig.ModelSpec{Name: "private"}},
		{Model: runtimeconfig.ModelSpec{Name: "public"}, LegacyAlias: true},
	}

	if err := prepareModelDirectories(mounts, directory); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, "private"))
	if err != nil || !info.IsDir() {
		t.Fatalf("private model mount point: %v, %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "public")); !os.IsNotExist(err) {
		t.Fatalf("created an unused public model mount point: %v", err)
	}
}

func TestRegistryCredentialsDoNotMutateHostInputs(t *testing.T) {
	host := &shimconfig.ExternalConfig{Secrets: map[string]string{"REGISTRY_GHCR_IO_USER": "user", "API_KEY": "host"}}
	resolved := secretstore.Store{"API_KEY": "resolved", "REGISTRY_GHCR_IO_TOKEN": "token"}
	values := registryCredentials(host, resolved)
	if values["API_KEY"] != "resolved" || values["REGISTRY_GHCR_IO_USER"] != "user" || values["REGISTRY_GHCR_IO_TOKEN"] != "token" {
		t.Fatal("registry credentials lost host or resolved values")
	}
	values["REGISTRY_GHCR_IO_TOKEN"] = "changed"
	if len(host.Secrets) != 2 || host.Secrets["API_KEY"] != "host" || resolved["REGISTRY_GHCR_IO_TOKEN"] != "token" {
		t.Fatal("registry preparation mutated its inputs")
	}
}
