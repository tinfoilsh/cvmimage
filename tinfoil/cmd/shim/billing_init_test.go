package main

import (
	"testing"

	"tinfoil/internal/config"
)

func TestNewShimBillingIsMandatoryForModelShim(t *testing.T) {
	modelConfig := &config.Config{
		ControlPlane: "https://api.tinfoil.test",
		ModelName:    "glm-5-2",
	}
	for _, secrets := range []map[string]string{
		nil,
	} {
		collector, err := newShimBilling(modelConfig, &config.ExternalConfig{Secrets: secrets})
		if err == nil || collector != nil {
			t.Fatalf("newShimBilling accepted incomplete secrets: %v", secrets)
		}
	}

	secrets := map[string]string{
		config.SecretUsageReporter: "reporter-secret",
	}
	collector, err := newShimBilling(modelConfig, &config.ExternalConfig{Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	if !collector.Enabled() {
		t.Fatal("newShimBilling returned a disabled collector")
	}
	collector.Stop()
}

func TestNewShimBillingRejectsInvalidControlPlane(t *testing.T) {
	modelConfig := &config.Config{ControlPlane: "http://api.tinfoil.test", ModelName: "glm-5-2"}
	secrets := map[string]string{
		config.SecretUsageReporter: "reporter-secret",
	}
	collector, err := newShimBilling(modelConfig, &config.ExternalConfig{Secrets: secrets})
	if err == nil || collector != nil {
		t.Fatalf("newShimBilling() = (%v, %v), want nil collector and error", collector, err)
	}
}

func TestNewShimBillingSkipsNonModelShim(t *testing.T) {
	collector, err := newShimBilling(&config.Config{}, &config.ExternalConfig{})
	if err != nil || collector != nil {
		t.Fatalf("newShimBilling non-model result = (%v, %v)", collector, err)
	}
}

func TestValidateShimBillingInvariant(t *testing.T) {
	modelConfig := &config.Config{ModelName: "test-model"}
	if err := validateShimBillingInvariant(modelConfig, nil); err == nil {
		t.Fatal("model shim accepted a nil billing collector")
	}
	if err := validateShimBillingInvariant(&config.Config{}, nil); err != nil {
		t.Fatalf("non-model shim unexpectedly required billing: %v", err)
	}
}
