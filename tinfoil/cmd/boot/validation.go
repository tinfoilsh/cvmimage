package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Input validation patterns
var (
	hexHashPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`) // SHA256 hex strings
	uuidPattern     = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	offsetPattern   = regexp.MustCompile(`^[0-9]+$`)                         // Numeric offset
	registryPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`) // Registry hostnames

	// imageDigestPattern requires an OCI digest pin so the pulled image is
	// byte-identical to what the attested config commits to.
	imageDigestPattern = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)

	// externalEnvDenyPattern blocks env keys that influence code loading or
	// model selection from being sourced from the unattested external config.
	externalEnvDenyPattern = regexp.MustCompile(`^(LD_.*|PYTHON.*|PATH|HF_.*|TRANSFORMERS_.*|VLLM_.*|MODEL.*|CUDA_.*|NVIDIA_.*)$`)
)

// disallowedCaps are Linux capabilities that grant near-root control of the
// host kernel or network namespace. Workload containers must not request them.
var disallowedCaps = map[string]bool{
	"SYS_ADMIN":       true,
	"NET_ADMIN":       true,
	"SYS_PTRACE":      true,
	"SYS_MODULE":      true,
	"SYS_RAWIO":       true,
	"SYS_BOOT":        true,
	"SYS_TIME":        true,
	"DAC_READ_SEARCH": true,
}

// validateContainers enforces security invariants on the attested container
// spec at config-load time so a misconfiguration fails the boot rather than
// silently weakening the workload isolation.
func validateContainers(containers []Container, debugMode bool) error {
	for _, c := range containers {
		if c.Image == "" {
			return fmt.Errorf("container %q: image is required", c.Name)
		}
		if !imageDigestPattern.MatchString(c.Image) {
			return fmt.Errorf("container %q: image %q must be pinned by digest (@sha256:<64-hex>)", c.Name, c.Image)
		}
		if !debugMode {
			if c.PidMode == "host" {
				return fmt.Errorf("container %q: pid=host is only permitted with tinfoil-debug=on", c.Name)
			}
			if c.IPC == "host" {
				return fmt.Errorf("container %q: ipc=host is only permitted with tinfoil-debug=on", c.Name)
			}
			for _, name := range c.CapAdd {
				if disallowedCaps[normalizeCap(name)] {
					return fmt.Errorf("container %q: capability %s is not permitted outside debug mode", c.Name, name)
				}
			}
		}
		for _, item := range c.Env {
			if key, ok := item.(string); ok && externalEnvDenyPattern.MatchString(key) {
				return fmt.Errorf("container %q: env key %q may not be sourced from external config (matches code-loading denylist)", c.Name, key)
			}
		}
		for _, key := range c.Secrets {
			if externalEnvDenyPattern.MatchString(key) {
				return fmt.Errorf("container %q: secret key %q may not be sourced from external config (matches code-loading denylist)", c.Name, key)
			}
		}
	}
	return nil
}

func normalizeCap(name string) string {
	return strings.TrimPrefix(strings.ToUpper(name), "CAP_")
}

// sha256Hash computes the SHA256 hash of data and returns hex string
func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
