// Package configtest gives tests the JSON form of a config written as YAML.
package configtest

import (
	"testing"

	sharedconfig "github.com/tinfoilsh/tinfoil-config"
)

const (
	// RuntimeDigest stands in for the manifest digest a cvm-version pins.
	RuntimeDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// CVMVersion pins the first runtime whose config is JSON.
	CVMVersion = sharedconfig.JSONConfigMinVersion + "@sha256:" + RuntimeDigest
	// YAMLCVMVersion pins the last runtime whose config is YAML.
	YAMLCVMVersion = "v0.15.5-rc.0@sha256:" + RuntimeDigest
)

// Workload is a config as a person writes it. It states each kind of value
// whose JSON form differs from its YAML form: fractional quantities, a
// duration, a literal environment value and a repository ID.
const Workload = `
cvm-version: ` + CVMVersion + `
cpus: 4
memory: 8192
shim:
  upstream-port: 8080
  rate-limit: 2.5
  drain_timeout: 90s
security:
  include-config-in-attestation: true
networks:
  app:
    egress: closed
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    provenance:
      github:
        repository: example/app
        repository_id: 123456789
        workflow: release.yml
        ref: refs/tags/v*
    restart: always
    cpus: 1.5
    env:
      - HF_TOKEN
      - PORT: 8080
    networks: [app]
    ports: ['2300:25565', '2301:8080']
  - name: sidecar
    image: example.com/sidecar@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
`

// JSON translates a config written as YAML into the JSON form the runtime
// boots.
func JSON(t testing.TB, yaml string) []byte {
	t.Helper()
	data, err := sharedconfig.ToJSON([]byte(yaml), sharedconfig.Options{})
	if err != nil {
		t.Fatalf("translating config to JSON: %v", err)
	}
	return data
}
