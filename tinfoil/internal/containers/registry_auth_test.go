package containers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"tinfoil/internal/ecrregistry"
)

// useDockerConfig points the pull auth lookup at a temporary config dir holding
// one credential per host (none when creds is nil), and poisons DOCKER_CONFIG so
// a lookup that falls back to the environment finds nothing.
func useDockerConfig(t *testing.T, creds map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if creds != nil {
		auths := make(map[string]map[string]string, len(creds))
		for host, userAndToken := range creds {
			auths[host] = map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(userAndToken))}
		}
		raw, err := json.Marshal(map[string]any{"auths": auths})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	previous := dockerConfigDir
	dockerConfigDir = dir
	t.Cleanup(func() { dockerConfigDir = previous })
}

type registryRefreshTransport func(*http.Request) (*http.Response, error)

func (f registryRefreshTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestImagePullRefreshOverridesExpiredStaticCredentials(t *testing.T) {
	const host = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
	useDockerConfig(t, map[string]string{host: "AWS:expired-deployment-password", "ghcr.io": "user:ghcr-password"})
	path := filepath.Join(dockerConfigDir, ecrregistry.ConfigFileName)
	require.NoError(t, ecrregistry.Configure(path, fmt.Sprintf(`{"host":%q,"org_id":"org_test","token":"refresh-secret"}`, host)))
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	calls := 0
	status := http.StatusOK
	http.DefaultTransport = registryRefreshTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, "api.tinfoil.sh", r.URL.Host)
		require.Equal(t, "Bearer refresh-secret", r.Header.Get("Authorization"))
		data, err := json.Marshal(ecrregistry.Credentials{Host: host, Username: "AWS", Password: fmt.Sprintf("fresh-%d", calls), ExpiresAt: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})
	for attempt := 1; attempt <= 2; attempt++ {
		auth, err := imagePullRegistryAuth(context.Background(), host+"/app:v1")
		require.NoError(t, err)
		user, password, server := decodeRegistryAuth(t, auth)
		require.Equal(t, "AWS", user)
		require.Equal(t, fmt.Sprintf("fresh-%d", attempt), password)
		require.Equal(t, host, server)
	}
	for _, image := range []string{"ghcr.io/org/app:v1", "999999999999.dkr.ecr.us-east-1.amazonaws.com/app:v1"} {
		_, err := imagePullRegistryAuth(context.Background(), image)
		require.NoError(t, err)
	}
	require.Equal(t, 2, calls)
	status = http.StatusUnauthorized
	auth, err := imagePullRegistryAuth(context.Background(), host+"/app:v1")
	require.Error(t, err)
	require.Empty(t, auth, "never fall back to an expired static password")
	require.NoError(t, os.WriteFile(path, []byte("corrupt refresh-secret"), 0600))
	_, err = imagePullRegistryAuth(context.Background(), host+"/app:v1")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "refresh-secret")
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
	useDockerConfig(t, nil)

	if got := registryAuth("ghcr.io/org/app:latest"); got != "" {
		t.Fatalf("expected anonymous pull without config, got %q", got)
	}
}
