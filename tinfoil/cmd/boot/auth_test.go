package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/docker/docker/api/types/registry"
)

func encodedCredential(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func dockerConfigJSON(registryKey, username, password string) string {
	return fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, registryKey, encodedCredential(username, password))
}

func writeDockerConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseDockerConfigAcceptsFixedSchema(t *testing.T) {
	data := dockerConfigJSON("us-docker.pkg.dev", "_json_key_base64", "service-account")
	config, err := parseDockerConfig([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Auths["us-docker.pkg.dev"].Auth; got != encodedCredential("_json_key_base64", "service-account") {
		t.Fatalf("auth = %q", got)
	}
}

func TestParseDockerConfigRejectsUnsupportedOrMalformedInput(t *testing.T) {
	tooManyAuths := make([]string, 0, maxDockerRegistries+1)
	for index := 0; index <= maxDockerRegistries; index++ {
		tooManyAuths = append(tooManyAuths, fmt.Sprintf(`"r%d":{"auth":%q}`, index, encodedCredential("user", "pass")))
	}
	oversizedCredential := encodedCredential("user", strings.Repeat("x", maxDecodedCredentialBytes))

	tests := map[string]string{
		"missing auths":         `{}`,
		"unknown top field":     `{"credsStore":"secretservice"}`,
		"credential helpers":    `{"auths":{},"credHelpers":{"example.com":"helper"}}`,
		"duplicate auths":       `{"auths":{},"auths":{}}`,
		"trailing document":     `{"auths":{}} {}`,
		"null auths":            `{"auths":null}`,
		"too many registries":   `{"auths":{` + strings.Join(tooManyAuths, ",") + `}}`,
		"empty registry":        `{"auths":{"":{"auth":"dXNlcjpwYXNz"}}}`,
		"long registry":         dockerConfigJSON(strings.Repeat("r", maxDockerRegistryKeyBytes+1), "user", "pass"),
		"duplicate registry":    `{"auths":{"example.com":{"auth":"dXNlcjpwYXNz"},"example.com":{"auth":"dXNlcjpwYXNz"}}}`,
		"missing auth":          `{"auths":{"example.com":{}}}`,
		"unknown auth field":    `{"auths":{"example.com":{"username":"user"}}}`,
		"duplicate auth field":  `{"auths":{"example.com":{"auth":"dXNlcjpwYXNz","auth":"dXNlcjpwYXNz"}}}`,
		"non-string auth":       `{"auths":{"example.com":{"auth":true}}}`,
		"empty auth":            `{"auths":{"example.com":{"auth":""}}}`,
		"malformed base64":      `{"auths":{"example.com":{"auth":"***"}}}`,
		"non-canonical base64":  `{"auths":{"example.com":{"auth":"Zh=="}}}`,
		"missing separator":     `{"auths":{"example.com":{"auth":"dXNlcg=="}}}`,
		"missing username":      `{"auths":{"example.com":{"auth":"OnBhc3M="}}}`,
		"missing password":      `{"auths":{"example.com":{"auth":"dXNlcjo="}}}`,
		"nul credential":        dockerConfigJSON("example.com", "us\x00er", "pass"),
		"oversized credential":  fmt.Sprintf(`{"auths":{"example.com":{"auth":%q}}}`, oversizedCredential),
		"unterminated document": `{"auths":{`,
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDockerConfig([]byte(data)); err == nil {
				t.Fatal("parseDockerConfig accepted invalid input")
			}
		})
	}

	if _, err := parseDockerConfig([]byte(strings.Repeat(" ", maxDockerConfigBytes+1))); err == nil {
		t.Fatal("parseDockerConfig accepted oversized input")
	}
}

func TestLoadDockerConfigRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"auths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}

	parent := filepath.Join(directory, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	parentConfig := filepath.Join(parent, "config.json")
	if err := os.WriteFile(parentConfig, []byte(`{"auths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(directory, "parent-link")
	if err := os.Symlink(parent, parentLink); err != nil {
		t.Fatal(err)
	}

	unsafePermissions := filepath.Join(directory, "unsafe.json")
	if err := os.WriteFile(unsafePermissions, []byte(`{"auths":{}}`), 0644); err != nil {
		t.Fatal(err)
	}

	oversized := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", maxDockerConfigBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"symlink":            symlink,
		"symlinked parent":   filepath.Join(parentLink, "config.json"),
		"directory":          directory,
		"unsafe permissions": unsafePermissions,
		"oversized":          oversized,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadDockerConfig(path); err == nil {
				t.Fatal("loadDockerConfig accepted unsafe file")
			}
		})
	}
}

func TestRegistryAuthForImageMatchesDockerCLIEncoding(t *testing.T) {
	path := writeDockerConfig(t, dockerConfigJSON("private.example.com", "alice", "secret"))
	got, err := registryAuthForImage(path, "private.example.com/team/image:latest")
	if err != nil {
		t.Fatal(err)
	}
	want := "eyJ1c2VybmFtZSI6ImFsaWNlIiwicGFzc3dvcmQiOiJzZWNyZXQiLCJzZXJ2ZXJhZGRyZXNzIjoicHJpdmF0ZS5leGFtcGxlLmNvbSJ9"
	if got != want {
		t.Fatalf("RegistryAuth = %q, want %q", got, want)
	}
}

func TestRegistryAuthForImagePreservesDockerHubAndGCP(t *testing.T) {
	for name, test := range map[string]struct {
		registryKey string
		image       string
		username    string
		password    string
	}{
		"docker hub": {
			registryKey: "docker.io",
			image:       "library/ubuntu:latest",
			username:    "docker-user",
			password:    "docker-token",
		},
		"docker hub CLI alias": {
			registryKey: "https://index.docker.io/v1/",
			image:       "ubuntu:latest",
			username:    "docker-user",
			password:    "docker-token",
		},
		"docker hub engine alias": {
			registryKey: "registry-1.docker.io",
			image:       "library/ubuntu:latest",
			username:    "docker-user",
			password:    "docker-token",
		},
		"localhost port": {
			registryKey: "localhost:5000",
			image:       "localhost:5000/team/image:latest",
			username:    "local-user",
			password:    "local-token",
		},
		"gcp": {
			registryKey: "us-docker.pkg.dev",
			image:       "us-docker.pkg.dev/project/repository/image:latest",
			username:    "_json_key_base64",
			password:    "base64-service-account",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeDockerConfig(t, dockerConfigJSON(test.registryKey, test.username, test.password))
			encoded, err := registryAuthForImage(path, test.image)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := registry.DecodeAuthConfig(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Username != test.username || decoded.Password != test.password || decoded.ServerAddress != test.registryKey {
				t.Fatalf("decoded RegistryAuth = %+v", decoded)
			}
		})
	}
}

func TestImageRegistryHost(t *testing.T) {
	for image, want := range map[string]string{
		"ubuntu:latest":                              dockerHubRegistry,
		"library/ubuntu:latest":                      dockerHubRegistry,
		"localhost/team/image:latest":                "localhost",
		"localhost:5000/team/image:latest":           "localhost:5000",
		"registry.example.com/team/image:latest":     "registry.example.com",
		"REGISTRY.EXAMPLE.COM:5000/image:latest":     "registry.example.com:5000",
		"registry-1.docker.io/library/ubuntu:latest": dockerHubRegistry,
	} {
		if got := imageRegistryHost(image); got != want {
			t.Errorf("imageRegistryHost(%q) = %q, want %q", image, got, want)
		}
	}
}

func TestRegistryAuthForImageLegacyRegistryKeyNormalization(t *testing.T) {
	path := writeDockerConfig(t, dockerConfigJSON("https://registry.example.com/v1/", "user", "pass"))
	encoded, err := registryAuthForImage(path, "registry.example.com/team/image:latest")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := registry.DecodeAuthConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ServerAddress != "https://registry.example.com/v1/" {
		t.Fatalf("server address = %q", decoded.ServerAddress)
	}
}

func TestRegistryAuthForImageMissingConfigOrRegistry(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	if auth, err := registryAuthForImage(missing, "ubuntu:latest"); err != nil || auth != "" {
		t.Fatalf("missing config: auth=%q err=%v", auth, err)
	}

	path := writeDockerConfig(t, dockerConfigJSON("private.example.com", "user", "pass"))
	if auth, err := registryAuthForImage(path, "other.example.com/image:latest"); err != nil || auth != "" {
		t.Fatalf("missing registry: auth=%q err=%v", auth, err)
	}
}

func TestRegistryAuthForImageConcurrentReads(t *testing.T) {
	path := writeDockerConfig(t, dockerConfigJSON("private.example.com", "user", "pass"))
	const goroutines = 32
	const readsPerGoroutine = 50

	var wait sync.WaitGroup
	errorsChannel := make(chan error, goroutines)
	for range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range readsPerGoroutine {
				auth, err := registryAuthForImage(path, "private.example.com/image:latest")
				if err != nil {
					errorsChannel <- err
					return
				}
				if auth == "" {
					errorsChannel <- errors.New("missing registry auth")
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}
