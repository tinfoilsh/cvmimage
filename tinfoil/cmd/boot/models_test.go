package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

func TestParseModelPackRef(t *testing.T) {
	ref := strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	got, err := parseModelPackRef(ref)
	if err != nil {
		t.Fatalf("expected valid model pack ref: %v", err)
	}
	if got.RootHash != strings.Repeat("a", 64) || got.HashOffset != "4096" || got.UUID != "0eefa619-50b7-588f-a072-d405fb439d36" {
		t.Fatalf("parsed ref mismatch: %+v", got)
	}
	if got.mapperName() != "mwp-"+strings.Repeat("a", 64) {
		t.Fatalf("mapper name mismatch: %s", got.mapperName())
	}
	if got.mountPoint() != boot.MWPDir+"/mwp-"+strings.Repeat("a", 64) {
		t.Fatalf("mount point mismatch: %s", got.mountPoint())
	}
	if got.legacyMountPoint() != boot.MPKDir+"/mpk-"+strings.Repeat("a", 64) {
		t.Fatalf("legacy mount point mismatch: %s", got.legacyMountPoint())
	}
	if got.artifactID() != strings.Repeat("a", 64)+"_0eefa619-50b7-588f-a072-d405fb439d36" {
		t.Fatalf("artifact ID mismatch: %s", got.artifactID())
	}

	tests := []struct {
		name string
		ref  string
	}{
		{
			name: "missing parts",
			ref:  strings.Repeat("a", 64) + "_4096",
		},
		{
			name: "bad UUID",
			ref:  strings.Repeat("a", 64) + "_4096_not-a-uuid",
		},
		{
			name: "bad root hash",
			ref:  "not-a-root_4096_0eefa619-50b7-588f-a072-d405fb439d36",
		},
		{
			name: "bad offset",
			ref:  strings.Repeat("a", 64) + "_not-an-offset_0eefa619-50b7-588f-a072-d405fb439d36",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseModelPackRef(tt.ref); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestModelPackRefForModel(t *testing.T) {
	ref := strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"

	for _, tt := range []struct {
		name     string
		model    ModelSpec
		wantKind modelKind
	}{
		{name: "legacy mpk", model: ModelSpec{Name: "legacy", MPK: ref}, wantKind: modelKindPlaintext},
		{name: "mwp", model: ModelSpec{Name: "plain", MWP: ref}, wantKind: modelKindPlaintext},
		{name: "emwp", model: ModelSpec{Name: "encrypted", EMWP: ref}, wantKind: modelKindEncrypted},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, kind, err := modelPackRefForModel(tt.model)
			if err != nil {
				t.Fatalf("expected model ref: %v", err)
			}
			if got.raw != ref {
				t.Fatalf("raw ref mismatch: got %q want %q", got.raw, ref)
			}
			if kind != tt.wantKind {
				t.Fatalf("kind mismatch: got %q want %q", kind, tt.wantKind)
			}
		})
	}

	for _, tt := range []struct {
		name  string
		model ModelSpec
	}{
		{name: "missing model ref", model: ModelSpec{Name: "missing"}},
		{name: "both mpk and mwp", model: ModelSpec{Name: "both", MPK: ref, MWP: ref}},
		{name: "both mwp and emwp", model: ModelSpec{Name: "both", MWP: ref, EMWP: ref}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := modelPackRefForModel(tt.model); err == nil {
				t.Fatal("expected model ref error")
			}
		})
	}
}

func TestEncryptedModelKey(t *testing.T) {
	key := strings.Repeat("k", defaultEMWPKeySize/8)
	spec := &modelPackRef{
		RootHash:   strings.Repeat("a", 64),
		HashOffset: "4096",
		UUID:       "0eefa619-50b7-588f-a072-d405fb439d36",
	}
	ext := &shimconfig.ExternalConfig{
		Secrets: map[string]string{
			"PRIVATE_MODEL_KEY": base64.StdEncoding.EncodeToString([]byte(key)),
		},
	}
	got, err := encryptedModelKey("PRIVATE_MODEL_KEY", spec, ext)
	if err != nil {
		t.Fatalf("expected derived key: %v", err)
	}
	if len(got) != defaultEMWPKeySize/8 {
		t.Fatalf("derived key length: got %d, want %d", len(got), defaultEMWPKeySize/8)
	}
	if bytes.Equal(got, []byte(key)) {
		t.Fatal("derived key should differ from external master key")
	}
	gotAgain, err := encryptedModelKey("PRIVATE_MODEL_KEY", spec, ext)
	if err != nil {
		t.Fatalf("expected repeat derived key: %v", err)
	}
	if !bytes.Equal(got, gotAgain) {
		t.Fatal("derived key should be deterministic for the same artifact")
	}
	otherSpec := *spec
	otherSpec.UUID = "1eefa619-50b7-588f-a072-d405fb439d36"
	otherGot, err := encryptedModelKey("PRIVATE_MODEL_KEY", &otherSpec, ext)
	if err != nil {
		t.Fatalf("expected other derived key: %v", err)
	}
	if bytes.Equal(got, otherGot) {
		t.Fatal("derived key should differ across artifacts")
	}

	for _, tc := range []struct {
		name string
		ext  *shimconfig.ExternalConfig
	}{
		{name: "missing external config"},
		{name: "missing secret", ext: &shimconfig.ExternalConfig{Secrets: map[string]string{}}},
		{name: "bad base64", ext: &shimconfig.ExternalConfig{Secrets: map[string]string{"PRIVATE_MODEL_KEY": "!"}}},
		{name: "short key", ext: &shimconfig.ExternalConfig{Secrets: map[string]string{"PRIVATE_MODEL_KEY": base64.StdEncoding.EncodeToString([]byte("short"))}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := encryptedModelKey("PRIVATE_MODEL_KEY", spec, tc.ext); err == nil {
				t.Fatal("expected key decode error")
			}
		})
	}
}
