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

func decodeYAMLDocument(data []byte) (*yaml.Node, error) {
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("input exceeds %d-byte limit", maxConfigFileBytes)
	}
	if err := validateYAMLStructureBudget(data); err != nil {
		return nil, err
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

func validateYAMLStructureBudget(data []byte) error {
	potentialNodes := 2
	flowDepth := 0
	var quote byte
	escaped := false
	blockHeaderIndent := -1
	blockContentIndent := -1

	for offset := 0; offset < len(data); {
		line, nextOffset := nextYAMLLine(data, offset)
		offset = nextOffset
		indent := yamlLineIndent(line)
		if blockHeaderIndent >= 0 {
			if yamlLineBlank(line) {
				continue
			}
			if blockContentIndent < 0 && indent > blockHeaderIndent {
				blockContentIndent = indent
				continue
			}
			if blockContentIndent >= 0 && indent >= blockContentIndent {
				continue
			}
			blockHeaderIndent = -1
			blockContentIndent = -1
		}

		lineOnlySpace := true
		for index := 0; index < len(line); index++ {
			character := line[index]
			if quote != 0 {
				if quote == '"' && escaped {
					escaped = false
					continue
				}
				if quote == '"' && character == '\\' {
					escaped = true
					continue
				}
				if character == quote {
					if quote == '\'' && index+1 < len(line) && line[index+1] == '\'' {
						index++
						continue
					}
					quote = 0
				}
				continue
			}

			if character == '#' && (index == 0 || isYAMLSeparation(line[index-1])) {
				break
			}
			switch character {
			case ' ', '\t':
				continue
			case '\'', '"':
				quote = character
				lineOnlySpace = false
			case '[', '{':
				potentialNodes++
				flowDepth++
				lineOnlySpace = false
			case ']', '}':
				if flowDepth > 0 {
					flowDepth--
				}
				lineOnlySpace = false
			case ',':
				if flowDepth > 0 {
					potentialNodes++
				}
				lineOnlySpace = false
			case ':':
				if flowDepth > 0 || index+1 == len(line) || isYAMLSeparation(line[index+1]) {
					potentialNodes += 2
				}
				lineOnlySpace = false
			case '-':
				if lineOnlySpace && (index+1 == len(line) || isYAMLSeparation(line[index+1])) {
					potentialNodes++
				}
				lineOnlySpace = false
			case '?':
				if lineOnlySpace && (index+1 == len(line) || isYAMLSeparation(line[index+1])) {
					potentialNodes += 2
				}
				lineOnlySpace = false
			case '|', '>':
				explicitIndent, ok := yamlBlockScalarHeader(line[index:])
				if flowDepth == 0 && ok && yamlBlockScalarPosition(line, index, indent) {
					blockHeaderIndent = indent
					blockContentIndent = -1
					if explicitIndent > 0 {
						blockContentIndent = indent + explicitIndent
					}
					index = len(line)
				}
				lineOnlySpace = false
			default:
				lineOnlySpace = false
			}
			if potentialNodes > maxYAMLNodes {
				return fmt.Errorf("YAML exceeds %d-node structural budget", maxYAMLNodes)
			}
		}
		if quote == '"' && escaped {
			escaped = false
		}
	}
	return nil
}

func nextYAMLLine(data []byte, offset int) ([]byte, int) {
	end := offset
	for end < len(data) && data[end] != '\n' && data[end] != '\r' {
		end++
	}
	next := end
	if next < len(data) {
		if data[next] == '\r' && next+1 < len(data) && data[next+1] == '\n' {
			next += 2
		} else {
			next++
		}
	}
	return data[offset:end], next
}

func yamlLineIndent(line []byte) int {
	indent := 0
	for indent < len(line) && line[indent] == ' ' {
		indent++
	}
	return indent
}

func yamlLineBlank(line []byte) bool {
	for _, character := range line {
		if character != ' ' && character != '\t' {
			return false
		}
	}
	return true
}

func yamlBlockScalarHeader(header []byte) (int, bool) {
	if len(header) == 0 || header[0] != '|' && header[0] != '>' {
		return 0, false
	}
	explicitIndent := 0
	seenChomp := false
	for index := 1; index < len(header); index++ {
		character := header[index]
		switch {
		case character == '+' || character == '-':
			if seenChomp {
				return 0, false
			}
			seenChomp = true
		case character >= '1' && character <= '9':
			if explicitIndent != 0 {
				return 0, false
			}
			explicitIndent = int(character - '0')
		case character == ' ' || character == '\t':
			for index < len(header) && (header[index] == ' ' || header[index] == '\t') {
				index++
			}
			return explicitIndent, index == len(header) || header[index] == '#'
		default:
			return 0, false
		}
	}
	return explicitIndent, true
}

func yamlBlockScalarPosition(line []byte, index, indent int) bool {
	if index == indent {
		return true
	}
	if index == 0 || !isYAMLSeparation(line[index-1]) {
		return false
	}
	for previous := index - 1; previous >= 0; previous-- {
		if line[previous] == ' ' || line[previous] == '\t' {
			continue
		}
		return line[previous] == ':' || line[previous] == '-' || line[previous] == '?'
	}
	return false
}

func isYAMLSeparation(character byte) bool {
	return character == ' ' || character == '\t' || character == '\r' || character == '\n'
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
