package containers

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeDockerConfig(t *testing.T, dir, host, user, token string) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
	cfg := `{"auths":{"` + host + `":{"auth":"` + auth + `"}}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func decodeRegistryAuth(t *testing.T, encoded string) (username, password, server string) {
	t.Helper()
	raw, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode RegistryAuth: %v", err)
	}
	var auth struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}
	if err := json.Unmarshal(raw, &auth); err != nil {
		t.Fatalf("unmarshal RegistryAuth: %v", err)
	}
	return auth.Username, auth.Password, auth.ServerAddress
}

func TestRegistryAuthReadsConfigDir(t *testing.T) {
	dir := t.TempDir()
	writeDockerConfig(t, dir, "ghcr.io", "octocat", "ghp_secret")

	// The pull must not depend on the caller's environment: point DOCKER_CONFIG
	// at an empty directory and make sure the explicit path still wins.
	t.Setenv("DOCKER_CONFIG", t.TempDir())

	encoded := registryAuth(dir, "ghcr.io/org/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if encoded == "" {
		t.Fatal("expected registry auth for ghcr.io image")
	}
	user, pass, server := decodeRegistryAuth(t, encoded)
	if user != "octocat" || pass != "ghp_secret" || server != "ghcr.io" {
		t.Fatalf("unexpected auth %q/%q@%q", user, pass, server)
	}

	if got := registryAuth(dir, "docker.io/library/nginx:latest"); got != "" {
		t.Fatalf("expected no auth for docker.io, got %q", got)
	}
}

func TestRegistryAuthMissingConfigIsAnonymous(t *testing.T) {
	if got := registryAuth(t.TempDir(), "ghcr.io/org/app:latest"); got != "" {
		t.Fatalf("expected anonymous pull without config, got %q", got)
	}
}
