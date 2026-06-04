package main

import (
	"encoding/base64"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestValidateEncryptedModelPack(t *testing.T) {
	valid := &EncryptedModelPackSpec{
		Device:          "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_tinfoil-private-model1",
		RootHash:        strings.Repeat("a", 64),
		HashOffset:      "4096",
		UUID:            "0eefa619-50b7-588f-a072-d405fb439d36",
		KeySecret:       "PRIVATE_MODEL_KEY",
		EncryptedSHA256: strings.Repeat("b", 64),
		DataBlockSize:   4096,
		HashBlockSize:   4096,
		DataBlocks:      "123",
	}
	if err := validateEncryptedModelPack(valid); err != nil {
		t.Fatalf("expected valid encrypted model pack: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*EncryptedModelPackSpec)
	}{
		{
			name: "device outside by-id",
			mutate: func(s *EncryptedModelPackSpec) {
				s.Device = "/tmp/model.img"
			},
		},
		{
			name: "bad root hash",
			mutate: func(s *EncryptedModelPackSpec) {
				s.RootHash = "not-a-root"
			},
		},
		{
			name: "bad key secret",
			mutate: func(s *EncryptedModelPackSpec) {
				s.KeySecret = "PRIVATE-MODEL-KEY"
			},
		},
		{
			name: "unsupported cipher",
			mutate: func(s *EncryptedModelPackSpec) {
				s.Cipher = "aes-cbc-plain"
			},
		},
		{
			name: "unsupported key size",
			mutate: func(s *EncryptedModelPackSpec) {
				s.KeySize = 256
			},
		},
		{
			name: "unsupported sector size",
			mutate: func(s *EncryptedModelPackSpec) {
				s.SectorSize = 512
			},
		},
		{
			name: "verify requires sha",
			mutate: func(s *EncryptedModelPackSpec) {
				s.EncryptedSHA256 = ""
				s.VerifyEncryptedSHA256 = true
			},
		},
		{
			name: "unsupported data block size",
			mutate: func(s *EncryptedModelPackSpec) {
				s.DataBlockSize = 8192
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := *valid
			tt.mutate(&spec)
			if err := validateEncryptedModelPack(&spec); err == nil {
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
	spec := &EncryptedModelPackSpec{KeySecret: "PRIVATE_MODEL_KEY"}

	got, err := encryptedModelKey(spec, ext)
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
			if _, err := encryptedModelKey(spec, tc.ext); err == nil {
				t.Fatal("expected key decode error")
			}
		})
	}
}
