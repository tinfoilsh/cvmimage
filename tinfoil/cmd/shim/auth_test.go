package main

import (
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestBuildAPIKeyValidatorFailsClosed(t *testing.T) {
	if validator, err := buildAPIKeyValidator(&shimconfig.Config{}); err != nil || validator != nil {
		t.Fatalf("unauthenticated validator = %v, err = %v", validator, err)
	}
	if _, err := buildAPIKeyValidator(&shimconfig.Config{Authenticated: true}); err == nil {
		t.Fatal("authenticated mode accepted an empty control-plane URL")
	}
	validator, err := buildAPIKeyValidator(&shimconfig.Config{Authenticated: true, ControlPlane: "https://api.tinfoil.sh"})
	if err != nil || validator == nil {
		t.Fatalf("authenticated validator = %v, err = %v", validator, err)
	}
}
