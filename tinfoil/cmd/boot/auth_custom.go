package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"

	shimconfig "tinfoil/internal/config"
)

const (
	secretCustomRegistryAuth       = "CUSTOM_REGISTRY_AUTH"
	customRegistryMaxBytes         = 64 << 10
	customRegistryHostMaxBytes     = 253
	customRegistryUsernameMaxBytes = 1024
	customRegistryTokenMaxBytes    = 16 << 10
)

var customRegistryHostPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type customRegistryCredentials struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

func customRegistryAuth(ext *shimconfig.ExternalConfig) (*customRegistryCredentials, error) {
	if ext == nil {
		return nil, nil
	}
	value, supplied := ext.Secrets[secretCustomRegistryAuth]
	if !supplied {
		return nil, nil
	}
	if len(value) > customRegistryMaxBytes {
		return nil, fmt.Errorf("CUSTOM_REGISTRY_AUTH exceeds the size limit")
	}
	var credentials customRegistryCredentials
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return nil, fmt.Errorf("CUSTOM_REGISTRY_AUTH must contain host, username, and token as JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("CUSTOM_REGISTRY_AUTH must contain a single JSON object")
	}
	if len(credentials.Host) > customRegistryHostMaxBytes || !customRegistryHostPattern.MatchString(credentials.Host) {
		return nil, fmt.Errorf("CUSTOM_REGISTRY_AUTH host must be a lowercase DNS hostname without a scheme, port, or path")
	}
	if strings.TrimSpace(credentials.Username) == "" || strings.TrimSpace(credentials.Token) == "" {
		return nil, fmt.Errorf("CUSTOM_REGISTRY_AUTH requires a username and token")
	}
	if len(credentials.Username) > customRegistryUsernameMaxBytes || len(credentials.Token) > customRegistryTokenMaxBytes {
		return nil, fmt.Errorf("CUSTOM_REGISTRY_AUTH credentials exceed the size limit")
	}
	if strings.Contains(credentials.Username, ":") || strings.IndexFunc(credentials.Username, unicode.IsControl) >= 0 || strings.IndexFunc(credentials.Token, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("CUSTOM_REGISTRY_AUTH credentials contain unsupported characters")
	}
	return &credentials, nil
}
