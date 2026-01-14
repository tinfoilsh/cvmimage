package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	shimBinaryPath  = "/mnt/ramdisk/tfshim"
	shimConfigPath  = "/mnt/ramdisk/shim.yml"
	shimDownloadURL = "https://github.com/tinfoilsh/tfshim/releases/download/%s/tfshim"
)

// installAndStartShim downloads, verifies, and starts the tfshim service
func installAndStartShim(config *Config) error {
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

	slog.Info("downloading tfshim", "version", version)

	// Download tfshim binary
	downloadURL := fmt.Sprintf(shimDownloadURL, version)
	if err := downloadFile(shimBinaryPath, downloadURL); err != nil {
		return fmt.Errorf("downloading tfshim: %w", err)
	}

	// Make executable
	if err := os.Chmod(shimBinaryPath, 0755); err != nil {
		return fmt.Errorf("chmod tfshim: %w", err)
	}

	// Verify hash
	actualHash, err := fileHash(shimBinaryPath)
	if err != nil {
		return fmt.Errorf("hashing tfshim: %w", err)
	}

	if actualHash != expectedHash {
		return fmt.Errorf("tfshim hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	slog.Info("tfshim hash verified", "hash", actualHash)

	// Write shim config
	shimConfigData, err := yaml.Marshal(config.Shim)
	if err != nil {
		return fmt.Errorf("marshaling shim config: %w", err)
	}

	if err := os.WriteFile(shimConfigPath, shimConfigData, 0644); err != nil {
		return fmt.Errorf("writing shim config: %w", err)
	}

	// Start tfshim service
	slog.Info("starting tfshim service")
	if err := startSystemdUnit("tfshim.service"); err != nil {
		return fmt.Errorf("starting tfshim: %w", err)
	}

	return nil
}

// downloadFile downloads a URL to a local file
func downloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// fileHash computes the SHA256 hash of a file
func fileHash(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
