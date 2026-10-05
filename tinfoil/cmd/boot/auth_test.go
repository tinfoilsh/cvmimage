package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	shimconfig "tinfoil/internal/config"
)

func TestRegistryAuthExactHostAndRotation(t *testing.T) {
	const host = "harbor.my-company.com"
	dir := t.TempDir()
	dockerDir := filepath.Join(dir, "docker-config")
	for _, token := range []string{`first:token+with/characters=`, `rotated-token`} {
		wire := `secrets:
  CUSTOM_REGISTRY_AUTH: '{"host":"harbor.my-company.com","username":"robot$project+puller","token":"` + token + `"}'
  REGISTRY_HARBOR_MY_COMPANY_COM_USER: legacy-user
  REGISTRY_HARBOR_MY_COMPANY_COM_TOKEN: other-host-token
  REGISTRY_DOCKER_IO_USER: docker-user
  REGISTRY_DOCKER_IO_TOKEN: docker-token
  REGISTRY_GHCR_IO_USER: github-user
  REGISTRY_GHCR_IO_TOKEN: github-token
`
		ext, err := shimconfig.DecodeExternal([]byte(wire))
		require.NoError(t, err)
		require.NoError(t, setupRegistryAuthAt(ext, dockerDir, filepath.Join(dir, "gcloud.json")))
		cfg, err := dockerconfig.Load(dockerDir)
		require.NoError(t, err)
		require.Len(t, cfg.AuthConfigs, 4)
		for _, tc := range []struct{ host, user, password string }{
			{host, "robot$project+puller", token},
			{"harbor.my.company.com", "legacy-user", "other-host-token"},
			{dockerHubAuthKey, "docker-user", "docker-token"},
			{"ghcr.io", "github-user", "github-token"},
			{"other.example.com", "", ""},
		} {
			auth, err := cfg.GetAuthConfig(tc.host)
			require.NoError(t, err)
			require.Equal(t, tc.user, auth.Username, tc.host)
			require.Equal(t, tc.password, auth.Password, tc.host)
		}
	}
	info, err := os.Stat(filepath.Join(dockerDir, "config.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	info, err = os.Stat(dockerDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestRegistryAuthRejectsInvalidCustomCredentials(t *testing.T) {
	const valid = `{"host":"harbor.my-company.com","username":"robot$project+puller","token":"sensitive-token"}`
	cases := map[string]string{
		"empty supplied secret": "",
		"unknown field":         strings.Replace(valid, `"token":`, `"sensitive-field":`, 1),
		"trailing object":       valid + `{}`,
		"null":                  `null`,
		"scheme":                strings.Replace(valid, "harbor.my-company.com", "https://harbor.my-company.com", 1),
		"empty token":           strings.Replace(valid, "sensitive-token", "", 1),
		"oversized token":       strings.Replace(valid, "sensitive-token", strings.Repeat("a", customRegistryTokenMaxBytes+1), 1),
		"colon in username":     strings.Replace(valid, "robot$project+puller", "robot:puller", 1),
		"control in token":      strings.Replace(valid, "sensitive-token", `sensitive-token\n`, 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			wire, err := yaml.Marshal(map[string]any{"secrets": map[string]string{secretCustomRegistryAuth: value}})
			require.NoError(t, err)
			ext, err := shimconfig.DecodeExternal(wire)
			require.NoError(t, err)
			dir := t.TempDir()
			err = setupRegistryAuthAt(ext, filepath.Join(dir, "docker"), filepath.Join(dir, "gcloud.json"))
			require.ErrorContains(t, err, "CUSTOM_REGISTRY_AUTH")
			require.NotContains(t, err.Error(), "sensitive")
			_, err = os.Stat(filepath.Join(dir, "docker", "config.json"))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestRegistryAuthRejectsConflictingSources(t *testing.T) {
	for _, tc := range []struct{ host, legacy string }{
		{"harbor.example.com", "  REGISTRY_HARBOR_EXAMPLE_COM_TOKEN: legacy-token\n"},
		{"harbor.example.com", "  GCLOUD_REGISTRY: harbor.example.com\n  GCLOUD_KEY: '{}'\n"},
		{"docker.io", "  GCLOUD_REGISTRY: index.docker.io\n  GCLOUD_KEY: '{}'\n"},
	} {
		ext, err := shimconfig.DecodeExternal([]byte(`secrets:
  CUSTOM_REGISTRY_AUTH: '{"host":"` + tc.host + `","username":"robot","token":"sensitive-token"}'
` + tc.legacy))
		require.NoError(t, err)
		dir := t.TempDir()
		err = setupRegistryAuthAt(ext, filepath.Join(dir, "docker"), filepath.Join(dir, "gcloud.json"))
		require.EqualError(t, err, "custom registry conflicts with another supplied registry credential")
		_, err = os.Stat(filepath.Join(dir, "docker", "config.json"))
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}

func TestRegistryAuthWithoutCustomCredentials(t *testing.T) {
	dir := t.TempDir()
	dockerDir := filepath.Join(dir, "docker")
	require.NoError(t, setupRegistryAuthAt(nil, dockerDir, filepath.Join(dir, "gcloud.json")))
	_, err := os.Stat(filepath.Join(dockerDir, "config.json"))
	require.ErrorIs(t, err, os.ErrNotExist)
	ext, err := shimconfig.DecodeExternal([]byte("secrets:\n  REGISTRY_GHCR_IO_USER: user\n  REGISTRY_GHCR_IO_TOKEN: token\n"))
	require.NoError(t, err)
	require.NoError(t, setupRegistryAuthAt(ext, dockerDir, filepath.Join(dir, "gcloud.json")))
	cfg, err := dockerconfig.Load(dockerDir)
	require.NoError(t, err)
	auth, err := cfg.GetAuthConfig("ghcr.io")
	require.NoError(t, err)
	require.Equal(t, "user", auth.Username)
	require.Equal(t, "token", auth.Password)
}
