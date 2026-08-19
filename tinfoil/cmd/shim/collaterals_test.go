package main

import (
	"encoding/json"
	"os"
	"testing"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/config"
)

func TestLoadCollateralRequest(t *testing.T) {
	want := wire.Request{
		Repo:        "tinfoilsh/workload",
		Tag:         "v1",
		Platform:    "tdx",
		QuoteBase64: "cXVvdGU=",
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/collateral-request.json"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadCollateralRequest(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("request = %#v, want %#v", got, want)
	}
}

func TestNewCollateralSourceSkipsDummy(t *testing.T) {
	source, err := newCollateralSource(wire.Request{Repo: "repo", Platform: "dummy"}, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if source != nil {
		t.Fatal("dummy collateral source was created")
	}
}
