package main

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateConfigShapeEnforcesCollectionLimits(t *testing.T) {
	networks := make(map[string]*NetworkSpec, maxConfigNetworks+1)
	for index := 0; index <= maxConfigNetworks; index++ {
		networks[fmt.Sprintf("network-%d", index)] = &NetworkSpec{}
	}
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{name: "containers", config: Config{Containers: make([]Container, maxConfigContainers+1)}, want: "containers exceeds"},
		{name: "models", config: Config{Models: make([]ModelSpec, maxConfigModels+1)}, want: "models exceeds"},
		{name: "networks", config: Config{Networks: networks}, want: "networks exceeds"},
		{name: "ports", config: Config{CVMNetwork: CVMNetworkConfig{InboundPorts: make([]int, maxConfigInboundPorts+1)}}, want: "inbound-ports exceeds"},
		{name: "command", config: Config{Containers: []Container{{Command: make([]string, maxContainerListEntries+1)}}}, want: "command exceeds"},
		{name: "allow", config: Config{Networks: map[string]*NetworkSpec{"web": {Allow: make([]string, maxNetworkAllowEntries+1)}}}, want: "allow exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfigShape(&test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateConfigShape error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateConfigShapeRejectsNestedOrAmbiguousEnv(t *testing.T) {
	for name, item := range map[string]interface{}{
		"invalid name":  "BAD-NAME",
		"long name":     strings.Repeat("A", maxEnvironmentNameBytes+1),
		"multiple keys": map[string]interface{}{"A": "1", "B": "2"},
		"nested value":  map[string]interface{}{"A": map[string]interface{}{"B": "2"}},
		"sequence":      []interface{}{"A"},
	} {
		t.Run(name, func(t *testing.T) {
			config := Config{Containers: []Container{{Env: []interface{}{item}}}}
			if err := validateConfigShape(&config); err == nil {
				t.Fatalf("validateConfigShape accepted %s", name)
			}
		})
	}
}

func TestNetworkSpecRejectsUnknownOrNonMappingShape(t *testing.T) {
	for name, data := range map[string]string{
		"unknown":   "egress: closed\nunexpected: true\n",
		"sequence":  "- closed\n",
		"scalar":    "closed\n",
		"duplicate": "egress: closed\negress: allowlist\n",
	} {
		t.Run(name, func(t *testing.T) {
			var network NetworkSpec
			if err := yaml.Unmarshal([]byte(data), &network); err == nil {
				t.Fatalf("NetworkSpec accepted %s shape", name)
			}
		})
	}
}
