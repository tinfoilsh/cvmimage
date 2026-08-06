package main

import (
	"net/url"
	"testing"

	"tinfoil/internal/key/online"
)

func TestBuildAPIKeyValidatorUsesOnlineValidation(t *testing.T) {
	controlPlaneURL, err := url.Parse("https://control-plane.example")
	if err != nil {
		t.Fatal(err)
	}
	validator, err := buildAPIKeyValidator(controlPlaneURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := validator.(*online.Validator); !ok {
		t.Fatalf("validator type = %T, want *online.Validator", validator)
	}
}
