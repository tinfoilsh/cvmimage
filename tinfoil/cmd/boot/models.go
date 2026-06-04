package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

const (
	defaultEMPKCipher     = "aes-xts-plain64"
	defaultEMPKKeySize    = 512
	defaultEMPKSectorSize = 4096
)

// mountModels mounts all model packs from the config
func mountModels(config *Config, externalConfig *shimconfig.ExternalConfig) error {
	if len(config.Models) == 0 {
		log.Println("No models to mount")
		return nil
	}

	log.Printf("Mounting %d model packs", len(config.Models))
	for _, model := range config.Models {
		switch {
		case model.MPK != "" && model.EMPK != "":
			return fmt.Errorf("model %q specifies both mpk and empk", model.Name)
		case model.MPK != "":
			if err := mountModelPack(model.MPK); err != nil {
				return fmt.Errorf("mounting model pack %s: %w", model.MPK, err)
			}
		case model.EMPK != "":
			if err := mountEncryptedModelPack(model, externalConfig); err != nil {
				return fmt.Errorf("mounting encrypted model pack %q: %w", model.Name, err)
			}
		default:
			return fmt.Errorf("model %q specifies neither mpk nor empk", model.Name)
		}
	}

	return nil
}

// mountModelPack mounts a model pack using dm-verity
// MPK format: rootHash_hashOffset_uuid
func mountModelPack(mpk string) error {
	spec, err := parseModelPackRef(mpk)
	if err != nil {
		return fmt.Errorf("invalid MPK format: %s: %w", mpk, err)
	}

	deviceName := fmt.Sprintf("mpk-%s", spec.RootHash)
	mountPoint := fmt.Sprintf("%s/%s", boot.MPKDir, deviceName)

	log.Printf("Opening verity device %s (uuid=%s)", deviceName, spec.UUID)
	if err := openAndMountVerity(diskByUUID(spec.UUID), deviceName, spec.RootHash, spec.HashOffset, mountPoint); err != nil {
		return err
	}

	log.Printf("Mounted model pack %s at %s", deviceName, mountPoint)
	return nil
}

// mountEncryptedModelPack mounts an encrypted model pack using dm-crypt below
// dm-verity. The decrypted mapper contains the same plaintext layout as an MPK:
// a read-only filesystem followed by its dm-verity hash tree.
func mountEncryptedModelPack(model ModelSpec, externalConfig *shimconfig.ExternalConfig) error {
	spec, err := parseModelPackRef(model.EMPK)
	if err != nil {
		return fmt.Errorf("invalid EMPK format: %s: %w", model.EMPK, err)
	}

	key, err := encryptedModelKey(model.KeySecret, externalConfig)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(boot.ModelKeyDir, 0700); err != nil {
		return fmt.Errorf("creating model key directory: %w", err)
	}
	keyFile := fmt.Sprintf("%s/%s.key", boot.ModelKeyDir, spec.RootHash)
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return fmt.Errorf("writing model key file: %w", err)
	}

	cryptName := fmt.Sprintf("empk-%s-crypt", spec.RootHash)
	verityName := fmt.Sprintf("mpk-%s", spec.RootHash)
	mountPoint := fmt.Sprintf("%s/%s", boot.MPKDir, verityName)

	log.Printf("Opening encrypted model pack %s (uuid=%s)", modelLogName(model.Name, spec.RootHash), spec.UUID)
	cryptCmd := exec.Command(
		"cryptsetup", "open",
		"--type", "plain",
		"--cipher", defaultEMPKCipher,
		"--key-size", strconv.Itoa(defaultEMPKKeySize),
		"--sector-size", strconv.Itoa(defaultEMPKSectorSize),
		"--key-file", keyFile,
		diskByUUID(spec.UUID),
		cryptName,
	)
	cryptCmd.Stdout = os.Stdout
	cryptCmd.Stderr = os.Stderr
	if err := cryptCmd.Run(); err != nil {
		return fmt.Errorf("cryptsetup open: %w", err)
	}

	cryptDevice := "/dev/mapper/" + cryptName
	if err := openAndMountVerity(cryptDevice, verityName, spec.RootHash, spec.HashOffset, mountPoint); err != nil {
		closeCryptMapper(cryptName)
		return err
	}

	log.Printf("Mounted encrypted model pack %s at %s", modelLogName(model.Name, spec.RootHash), mountPoint)
	return nil
}

type modelPackRef struct {
	RootHash   string
	HashOffset string
	UUID       string
}

func parseModelPackRef(ref string) (*modelPackRef, error) {
	parts := strings.Split(ref, "_")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected rootHash_hashOffset_uuid")
	}

	spec := &modelPackRef{
		RootHash:   parts[0],
		HashOffset: parts[1],
		UUID:       parts[2],
	}
	if !hexHashPattern.MatchString(spec.RootHash) {
		return nil, fmt.Errorf("invalid root hash format: %s", spec.RootHash)
	}
	if !offsetPattern.MatchString(spec.HashOffset) {
		return nil, fmt.Errorf("invalid hash offset format: %s", spec.HashOffset)
	}
	if !uuidPattern.MatchString(spec.UUID) {
		return nil, fmt.Errorf("invalid UUID format: %s", spec.UUID)
	}
	return spec, nil
}

func encryptedModelKey(keySecret string, externalConfig *shimconfig.ExternalConfig) ([]byte, error) {
	if !secretNamePattern.MatchString(keySecret) {
		return nil, fmt.Errorf("invalid key secret name: %s", keySecret)
	}
	if externalConfig == nil {
		return nil, fmt.Errorf("external config is required for encrypted model key %q", keySecret)
	}
	secret := externalConfig.GetSecret(keySecret)
	if secret == "" {
		return nil, fmt.Errorf("encrypted model key secret %q not found", keySecret)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted model key secret %q as base64: %w", keySecret, err)
	}
	if len(key) != defaultEMPKKeySize/8 {
		return nil, fmt.Errorf("encrypted model key secret %q decoded to %d bytes, want %d", keySecret, len(key), defaultEMPKKeySize/8)
	}
	return key, nil
}

func openAndMountVerity(sourceDevice, deviceName, rootHash, hashOffset, mountPoint string) error {
	// Using veritysetup as there's no good pure-Go dm-verity library.
	cmd := exec.Command(
		"veritysetup", "open",
		sourceDevice,
		deviceName,
		sourceDevice,
		rootHash,
		"--hash-offset="+hashOffset,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("veritysetup open: %w", err)
	}

	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		closeVerityMapper(deviceName)
		return fmt.Errorf("creating mount point: %w", err)
	}

	mountCmd := exec.Command(
		"mount", "-o", "ro",
		"/dev/mapper/"+deviceName,
		mountPoint,
	)
	mountCmd.Stdout = os.Stdout
	mountCmd.Stderr = os.Stderr
	if err := mountCmd.Run(); err != nil {
		closeVerityMapper(deviceName)
		return fmt.Errorf("mounting verity device: %w", err)
	}

	return nil
}

func diskByUUID(uuid string) string {
	return fmt.Sprintf("/dev/disk/by-uuid/%s", uuid)
}

func closeVerityMapper(name string) {
	_ = exec.Command("veritysetup", "close", name).Run()
}

func closeCryptMapper(name string) {
	_ = exec.Command("cryptsetup", "close", name).Run()
}

func modelLogName(name, rootHash string) string {
	if name != "" {
		return name
	}
	return "mpk-" + rootHash
}
