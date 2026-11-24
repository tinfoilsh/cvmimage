package config

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxConfigFileBytes    = 1 << 20
	maxJSONValues         = 16384
	maxJSONDepth          = 64
	maxExternalEntries    = 1024
	maxExternalKeyBytes   = 256
	maxExternalValueBytes = 64 << 10
	maxMetadataFieldBytes = 4096
	maxOperatorKeyBytes   = 256
)

func readConfigFile(path string) ([]byte, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
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
	var initialStat unix.Stat_t
	if err := unix.Fstat(descriptor, &initialStat); err != nil {
		return nil, err
	}
	if initialStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("not a regular file")
	}
	if initialStat.Size > maxConfigFileBytes {
		return nil, fmt.Errorf("exceeds %d-byte limit", maxConfigFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("exceeds %d-byte limit", maxConfigFileBytes)
	}
	var finalStat unix.Stat_t
	if err := unix.Fstat(descriptor, &finalStat); err != nil {
		return nil, err
	}
	if !sameConfigFileVersion(&initialStat, &finalStat) {
		return nil, fmt.Errorf("changed while being read")
	}
	return data, nil
}

func sameConfigFileVersion(initial, final *unix.Stat_t) bool {
	return initial.Size == final.Size &&
		initial.Mtim.Sec == final.Mtim.Sec && initial.Mtim.Nsec == final.Mtim.Nsec &&
		initial.Ctim.Sec == final.Ctim.Sec && initial.Ctim.Nsec == final.Ctim.Nsec
}

// decodeJSONObject reads data into target after holding it to the structure
// limits. The decoder itself refuses a repeated member name, text that is not
// UTF-8 and anything after the object.
func decodeJSONObject(data []byte, target any, options ...json.Options) error {
	if err := validateJSONStructure(data); err != nil {
		return err
	}
	return json.Unmarshal(data, target, options...)
}

// validateJSONStructure requires one JSON object within the size, nesting
// and value-count limits, before anything builds values from it. A member
// name counts as a value.
func validateJSONStructure(data []byte) error {
	if len(data) > maxConfigFileBytes {
		return fmt.Errorf("input exceeds %d-byte limit", maxConfigFileBytes)
	}
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	values := 0
	for {
		token, err := decoder.ReadToken()
		if err != nil {
			return err
		}
		kind := token.Kind()
		if values == 0 && kind != '{' {
			return fmt.Errorf("JSON document is not an object")
		}
		if kind == '}' || kind == ']' {
			if decoder.StackDepth() == 0 {
				return nil
			}
			continue
		}
		values++
		if values > maxJSONValues {
			return fmt.Errorf("JSON exceeds %d-value limit", maxJSONValues)
		}
		if decoder.StackDepth() > maxJSONDepth {
			return fmt.Errorf("JSON exceeds depth limit %d", maxJSONDepth)
		}
	}
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
		"shutdown_token":  config.ShutdownToken,
	} {
		if len(value) > maxMetadataFieldBytes || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%s exceeds safe value limits", field)
		}
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

func validateOperatorMap(section string, values map[string]jsontext.Value) error {
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
