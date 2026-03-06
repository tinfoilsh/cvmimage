package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	shimBinaryPath  = "/mnt/ramdisk/tfshim"
	shimConfigPath  = "/mnt/ramdisk/shim.yml"
	shimDownloadURL = "https://github.com/tinfoilsh/tfshim/releases/download/%s/tfshim"
)

// installShim downloads and verifies tfshim, then writes the config for systemd
func installShim(config *Config) error {
	// Parse shim-version: "v1.0.0@sha256:abc123..."
	shimInfo := config.ShimVersion
	if shimInfo == "" {
		return fmt.Errorf("shim-version not specified in config")
	}

	parts := strings.SplitN(shimInfo, "@sha256:", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid shim-version format: %s (expected version@sha256:hash)", shimInfo)
	}

	version := parts[0]
	expectedHash := parts[1]

	// Validate version format
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("invalid version format: %s", version)
	}

	// Validate hash format
	if !hexHashPattern.MatchString(expectedHash) {
		return fmt.Errorf("invalid hash format in shim-version: %s", expectedHash)
	}

	log.Printf("Downloading tfshim %s", version)

	// Download tfshim binary
	downloadURL := fmt.Sprintf(shimDownloadURL, version)
	if err := downloadFile(shimBinaryPath, downloadURL); err != nil {
		return fmt.Errorf("downloading tfshim: %w", err)
	}

	// Verify hash
	shimData, err := os.ReadFile(shimBinaryPath)
	if err != nil {
		return fmt.Errorf("reading tfshim: %w", err)
	}
	actualHash := sha256Hash(shimData)

	if actualHash != expectedHash { // Public values: no constant time comparison
		return fmt.Errorf("tfshim hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	log.Printf("Tfshim hash verified: %s", actualHash)

	// Make executable
	if err := os.Chmod(shimBinaryPath, 0755); err != nil {
		return fmt.Errorf("chmod tfshim: %w", err)
	}

	// Write shim config - systemd will auto-start tfshim.service
	shimConfigData, err := yaml.Marshal(config.Shim)
	if err != nil {
		return fmt.Errorf("marshaling shim config: %w", err)
	}

	if err := os.WriteFile(shimConfigPath, shimConfigData, 0644); err != nil {
		return fmt.Errorf("writing shim config: %w", err)
	}

	log.Println("Shim config written, systemd will auto-start tfshim.service")
	return nil
}

// downloadFile downloads a URL to a local file
func downloadFile(filepath string, url string) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("only HTTPS URLs are supported: %s", url)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", filepath, err)
	}
	defer out.Close()

	if _, err = io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("writing %s: %w", filepath, err)
	}
	return nil
}
