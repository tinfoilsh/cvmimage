package containers

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// useDockerConfig points the pull auth lookup at a temporary config dir holding
// one credential per host, and poisons DOCKER_CONFIG so a lookup that falls
// back to the environment finds nothing.
func useDockerConfig(t *testing.T, creds map[string]string) {
	t.Helper()
	auths := make(map[string]map[string]string, len(creds))
	for host, userAndToken := range creds {
		auths[host] = map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(userAndToken))}
	}
	raw, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	previous := dockerConfigDir
	dockerConfigDir = dir
	t.Cleanup(func() { dockerConfigDir = previous })
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

func TestRegistryAuthResolvesHostFromReference(t *testing.T) {
	// Keys as tinfoil-boot writes them: Docker Hub lives under the index URL.
	useDockerConfig(t, map[string]string{
		"ghcr.io":                     "octocat:ghp_secret",
		"localhost:5000":              "local:lpass",
		"https://index.docker.io/v1/": "hubuser:hubpass",
	})

	cases := []struct {
		image, user, pass, server string
	}{
		{"ghcr.io/org/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "octocat", "ghp_secret", "ghcr.io"},
		{"ghcr.io/org/app:v1", "octocat", "ghp_secret", "ghcr.io"},
		{"localhost:5000/app:v1", "local", "lpass", "localhost:5000"},
		{"nginx", "hubuser", "hubpass", "https://index.docker.io/v1/"},
		{"docker.io/library/nginx:latest", "hubuser", "hubpass", "https://index.docker.io/v1/"},
		{"index.docker.io/library/nginx:latest", "hubuser", "hubpass", "https://index.docker.io/v1/"},
	}
	for _, tc := range cases {
		encoded := registryAuth(tc.image)
		if encoded == "" {
			t.Errorf("%s: expected registry auth", tc.image)
			continue
		}
		user, pass, server := decodeRegistryAuth(t, encoded)
		if user != tc.user || pass != tc.pass || server != tc.server {
			t.Errorf("%s: got %q/%q@%q, want %q/%q@%q", tc.image, user, pass, server, tc.user, tc.pass, tc.server)
		}
	}
}

func TestRegistryAuthAnonymousWithoutCredential(t *testing.T) {
	useDockerConfig(t, map[string]string{"ghcr.io": "octocat:ghp_secret"})

	for _, image := range []string{
		"quay.io/org/app:v1", // host without an entry
		"nginx",              // Docker Hub without an entry
		"ghcr.io/Org/App:v1", // invalid reference (uppercase path)
	} {
		if got := registryAuth(image); got != "" {
			t.Errorf("%s: expected anonymous pull, got %q", image, got)
		}
	}
}

func TestRegistryAuthMissingConfigIsAnonymous(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	previous := dockerConfigDir
	dockerConfigDir = t.TempDir()
	t.Cleanup(func() { dockerConfigDir = previous })

	if got := registryAuth("ghcr.io/org/app:latest"); got != "" {
		t.Fatalf("expected anonymous pull without config, got %q", got)
	}
}
