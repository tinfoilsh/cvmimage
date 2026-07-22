package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	maxConfigFileBytes    = 1 << 20
	maxYAMLNodes          = 16384
	maxYAMLDepth          = 64
	maxExternalEntries    = 1024
	maxExternalKeyBytes   = 256
	maxExternalValueBytes = 64 << 10
	maxMetadataFieldBytes = 4096
	maxOperatorKeyBytes   = 256
)

func readConfigFile(path string) ([]byte, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		unix.Close(descriptor)
		return nil, fmt.Errorf("open descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Size() > maxConfigFileBytes {
		return nil, fmt.Errorf("exceeds %d-byte limit", maxConfigFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("exceeds %d-byte limit", maxConfigFileBytes)
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != finalInfo.Size() || !info.ModTime().Equal(finalInfo.ModTime()) {
		return nil, fmt.Errorf("changed while being read")
	}
	return data, nil
}

func decodeYAMLDocument(data []byte) (*yaml.Node, error) {
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("input exceeds %d-byte limit", maxConfigFileBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		return nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple YAML documents")
		}
		return nil, err
	}
	if err := validateYAMLTree(&node); err != nil {
		return nil, err
	}
	return &node, nil
}

func validateYAMLTree(root *yaml.Node) error {
	if root == nil {
		return fmt.Errorf("missing YAML document")
	}
	type pendingNode struct {
		node  *yaml.Node
		depth int
	}
	stack := []pendingNode{{node: root}}
	count := 0
	valueBytes := 0
	for len(stack) > 0 {
		last := len(stack) - 1
		pending := stack[last]
		stack = stack[:last]
		count++
		if count > maxYAMLNodes {
			return fmt.Errorf("YAML exceeds %d-node limit", maxYAMLNodes)
		}
		if pending.depth > maxYAMLDepth {
			return fmt.Errorf("YAML exceeds depth limit %d", maxYAMLDepth)
		}
		if pending.node.Kind == yaml.AliasNode || pending.node.Alias != nil {
			return fmt.Errorf("YAML aliases are not supported")
		}
		valueBytes += len(pending.node.Value) + len(pending.node.Tag) + len(pending.node.Anchor)
		if valueBytes > maxConfigFileBytes {
			return fmt.Errorf("YAML scalar data exceeds %d-byte limit", maxConfigFileBytes)
		}
		for index := len(pending.node.Content) - 1; index >= 0; index-- {
			stack = append(stack, pendingNode{
				node:  pending.node.Content[index],
				depth: pending.depth + 1,
			})
		}
	}
	return nil
}

func (config *ExternalConfig) validateBounds() error {
	if err := validateStringMap("env", config.Env); err != nil {
		return err
	}
	if err := validateStringMap("secrets", config.Secrets); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"metadata.id":     config.Metadata.ID,
		"metadata.domain": config.Metadata.Domain,
		"metadata.image":  config.Metadata.Image,
		"metadata.cpu":    config.Metadata.CPU,
		"metadata.gpu":    config.Metadata.GPU,
		"metadata.repo":   config.Metadata.Repo,
		"metadata.digest": config.Metadata.Digest,
		"network.address": networkValue(config.Network, true),
		"network.gateway": networkValue(config.Network, false),
	} {
		if len(value) > maxMetadataFieldBytes || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%s exceeds safe value limits", field)
		}
	}
	if len(config.VaultToken) > maxExternalValueBytes || strings.IndexByte(config.VaultToken, 0) >= 0 {
		return fmt.Errorf("vault-token exceeds safe value limits")
	}
	if err := validateOperatorMap("metadata", config.Metadata.Extra); err != nil {
		return err
	}
	return validateOperatorMap("external config", config.Extra)
}

func validateStringMap(section string, values map[string]string) error {
	if len(values) > maxExternalEntries {
		return fmt.Errorf("%s exceeds %d-entry limit", section, maxExternalEntries)
	}
	for key, value := range values {
		if !validEnvironmentKey(key) {
			return fmt.Errorf("%s contains invalid key %q", section, key)
		}
		if len(value) > maxExternalValueBytes || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%s value for %q exceeds safe limits", section, key)
		}
	}
	return nil
}

func validEnvironmentKey(key string) bool {
	if len(key) == 0 || len(key) > maxExternalKeyBytes {
		return false
	}
	for index := 0; index < len(key); index++ {
		character := key[index]
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' {
			continue
		}
		if index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func validateOperatorMap(section string, values map[string]yaml.Node) error {
	if len(values) > maxExternalEntries {
		return fmt.Errorf("%s exceeds %d-entry limit", section, maxExternalEntries)
	}
	for key := range values {
		if len(key) == 0 || len(key) > maxOperatorKeyBytes || strings.ContainsAny(key, "\x00\t\r\n") {
			return fmt.Errorf("%s contains invalid key %q", section, key)
		}
	}
	return nil
}

func networkValue(network *ExternalNetworkConfig, address bool) string {
	if network == nil {
		return ""
	}
	if address {
		return network.Address
	}
	return network.Gateway
}
