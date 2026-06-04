package main

import (
	"encoding/base64"
	"strings"
	"testing"

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

func TestEncryptedModelKey(t *testing.T) {
	key := strings.Repeat("k", defaultEMPKKeySize/8)
	ext := &shimconfig.ExternalConfig{
		Secrets: map[string]string{
			"PRIVATE_MODEL_KEY": base64.StdEncoding.EncodeToString([]byte(key)),
		},
	}
	got, err := encryptedModelKey("PRIVATE_MODEL_KEY", ext)
	if err != nil {
		t.Fatalf("expected decoded key: %v", err)
	}
	if string(got) != key {
		t.Fatalf("decoded key mismatch")
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
			if _, err := encryptedModelKey("PRIVATE_MODEL_KEY", tc.ext); err == nil {
				t.Fatal("expected key decode error")
			}
		})
	}
}
