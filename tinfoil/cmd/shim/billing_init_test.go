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
		{config.SecretUsageReporter: "reporter-secret"},
		{config.SecretUsageContext: "context-secret"},
	} {
		collector, _, err := newShimBilling(modelConfig, &config.ExternalConfig{Secrets: secrets})
		if err == nil || collector != nil {
			t.Fatalf("newShimBilling accepted incomplete secrets: %v", secrets)
		}
	}

	secrets := map[string]string{
		config.SecretUsageReporter: "reporter-secret",
		config.SecretUsageContext:  "context-secret",
	}
	collector, usageContextSecret, err := newShimBilling(modelConfig, &config.ExternalConfig{Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	if !collector.Enabled() {
		t.Fatal("newShimBilling returned a disabled collector")
	}
	if usageContextSecret != "context-secret" {
		t.Fatalf("usage context secret = %q", usageContextSecret)
	}
	collector.Stop()
}

func TestNewShimBillingRejectsInvalidControlPlane(t *testing.T) {
	modelConfig := &config.Config{ControlPlane: "http://api.tinfoil.test", ModelName: "glm-5-2"}
	secrets := map[string]string{
		config.SecretUsageReporter: "reporter-secret",
		config.SecretUsageContext:  "context-secret",
	}
	collector, _, err := newShimBilling(modelConfig, &config.ExternalConfig{Secrets: secrets})
	if err == nil || collector != nil {
		t.Fatalf("newShimBilling() = (%v, %v), want nil collector and error", collector, err)
	}
}

func TestNewShimBillingSkipsNonModelShim(t *testing.T) {
	collector, secret, err := newShimBilling(&config.Config{}, &config.ExternalConfig{})
	if err != nil || collector != nil || secret != "" {
		t.Fatalf("newShimBilling non-model result = (%v, %q, %v)", collector, secret, err)
	}
}

func TestValidateShimBillingInvariant(t *testing.T) {
	modelConfig := &config.Config{ModelName: "test-model"}
	if err := validateShimBillingInvariant(modelConfig, nil, "context-secret"); err == nil {
		t.Fatal("model shim accepted a nil billing collector")
	}
	if err := validateShimBillingInvariant(&config.Config{}, nil, ""); err != nil {
		t.Fatalf("non-model shim unexpectedly required billing: %v", err)
	}
}
