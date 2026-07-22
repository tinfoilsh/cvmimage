package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDecodeExternalRejectsAliasesAndBounds(t *testing.T) {
	tests := map[string][]byte{
		"alias":     []byte("metadata: &metadata\n  cpu: amd\ncopy: *metadata\n"),
		"oversized": []byte(strings.Repeat("x", maxConfigFileBytes+1)),
		"deep":      []byte(strings.Repeat("- ", maxYAMLDepth+1) + "value\n"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExternal(data); err == nil {
				t.Fatalf("DecodeExternal accepted %s input", name)
			}
		})
	}
}

func TestDecodeRejectsOversizedNodeTree(t *testing.T) {
	root := yaml.Node{Kind: yaml.DocumentNode}
	sequence := yaml.Node{Kind: yaml.SequenceNode}
	root.Content = []*yaml.Node{&sequence}
	for range maxYAMLNodes {
		sequence.Content = append(sequence.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "x"})
	}
	if _, err := Decode(&root); err == nil {
		t.Fatal("Decode accepted oversized YAML node tree")
	}
}

func TestDecodeRejectsOversizedScalarData(t *testing.T) {
	root := yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{
		Kind:  yaml.ScalarNode,
		Value: strings.Repeat("x", maxConfigFileBytes+1),
	}}}
	if _, err := Decode(&root); err == nil {
		t.Fatal("Decode accepted oversized scalar data")
	}
}

func TestDecodeExternalRejectsUnsafeMapsAndValues(t *testing.T) {
	tooMany := make(map[string]string, maxExternalEntries+1)
	for index := range maxExternalEntries + 1 {
		tooMany["KEY_"+string(rune(index+1))] = "value"
	}
	for name, config := range map[string]ExternalConfig{
		"env count":    {Env: tooMany},
		"env key":      {Env: map[string]string{"BAD-KEY": "value"}},
		"secret value": {Secrets: map[string]string{"KEY": strings.Repeat("x", maxExternalValueBytes+1)}},
		"metadata":     {Metadata: Metadata{Domain: strings.Repeat("x", maxMetadataFieldBytes+1)}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := config.validateBounds(); err == nil {
				t.Fatalf("validateBounds accepted %s", name)
			}
		})
	}
}

func TestLoadRejectsSymlinkAndOversizedFiles(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.yaml")
	if err := os.WriteFile(valid, []byte("upstream-port: 8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.yaml")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(symlink); err == nil {
		t.Fatal("readConfigFile accepted symlink")
	}
	parent := filepath.Join(directory, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	parentFile := filepath.Join(parent, "config.yaml")
	if err := os.WriteFile(parentFile, []byte("upstream-port: 8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(directory, "parent-link")
	if err := os.Symlink(parent, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(filepath.Join(parentLink, "config.yaml")); err == nil {
		t.Fatal("readConfigFile accepted symlinked parent")
	}
	oversized := filepath.Join(directory, "oversized.yaml")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", maxConfigFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(oversized); err == nil {
		t.Fatal("readConfigFile accepted oversized file")
	}
}
