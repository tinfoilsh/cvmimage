package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"tinfoil/internal/attestationmaterial"
)

func TestLoadCollateralRequest(t *testing.T) {
	want := attestationmaterial.Request{
		Repo:     "tinfoilsh/workload",
		Tag:      "v1",
		Version:  attestationmaterial.RequestVersionDocument,
		Document: json.RawMessage(`{}`),
	}
	got, err := loadCollateralRequest(writeCollateralRequestArtifact(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request = %#v, want %#v", got, want)
	}
}

func TestLoadCollateralRequestRejectsIncompleteArtifact(t *testing.T) {
	for name, request := range map[string]attestationmaterial.Request{
		"empty":            {},
		"missing document": {Version: attestationmaterial.RequestVersionDocument, Repo: "repo"},
		"missing repo":     {Version: attestationmaterial.RequestVersionDocument, Document: json.RawMessage(`{}`)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadCollateralRequest(writeCollateralRequestArtifact(t, request)); err == nil {
				t.Fatal("incomplete collateral request accepted")
			}
		})
	}
}

func writeCollateralRequestArtifact(t *testing.T, request attestationmaterial.Request) string {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/collateral-request.json"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
