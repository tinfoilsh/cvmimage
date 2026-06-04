package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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
		case model.MPK != "" && model.EMPK != nil:
			return fmt.Errorf("model %q specifies both mpk and empk", model.Name)
		case model.MPK != "":
			if err := mountModelPack(model.MPK); err != nil {
				return fmt.Errorf("mounting model pack %s: %w", model.MPK, err)
			}
		case model.EMPK != nil:
			if err := mountEncryptedModelPack(model.Name, model.EMPK, externalConfig); err != nil {
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
	parts := strings.Split(mpk, "_")
	if len(parts) != 3 {
		return fmt.Errorf("invalid MPK format: %s (expected rootHash_offset_uuid)", mpk)
	}

	rootHash := parts[0]
	offset := parts[1]
	uuid := parts[2]

	// Validate components to prevent injection/traversal attacks
	if !hexHashPattern.MatchString(rootHash) {
		return fmt.Errorf("invalid root hash format: %s", rootHash)
	}
	if !offsetPattern.MatchString(offset) {
		return fmt.Errorf("invalid offset format: %s", offset)
	}
	if !uuidPattern.MatchString(uuid) {
		return fmt.Errorf("invalid UUID format: %s", uuid)
	}

	blockDevice := fmt.Sprintf("/dev/disk/by-uuid/%s", uuid)
	deviceName := fmt.Sprintf("mpk-%s", rootHash)
	mountPoint := fmt.Sprintf("%s/%s", boot.MPKDir, deviceName)

	log.Printf("Opening verity device %s (uuid=%s)", deviceName, uuid)

	// Open dm-verity device
	// Using veritysetup as there's no good pure-Go dm-verity library
	cmd := exec.Command(
		"veritysetup", "open",
		blockDevice,
		deviceName,
		blockDevice,
		rootHash,
		"--hash-offset="+offset,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("veritysetup open: %w", err)
	}

	// Create mount point
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("creating mount point: %w", err)
	}

	// Mount the verified device read-only
	mountCmd := exec.Command(
		"mount", "-o", "ro",
		"/dev/mapper/"+deviceName,
		mountPoint,
	)
	mountCmd.Stdout = os.Stdout
	mountCmd.Stderr = os.Stderr

	if err := mountCmd.Run(); err != nil {
		return fmt.Errorf("mounting verity device: %w", err)
	}

	log.Printf("Mounted model pack %s at %s", deviceName, mountPoint)
	return nil
}

// mountEncryptedModelPack mounts an encrypted model pack using dm-crypt below
// dm-verity. The decrypted mapper contains the same plaintext layout as an MPK:
// a read-only filesystem followed by its dm-verity hash tree.
func mountEncryptedModelPack(name string, spec *EncryptedModelPackSpec, externalConfig *shimconfig.ExternalConfig) error {
	if err := validateEncryptedModelPack(spec); err != nil {
		return err
	}

	key, err := encryptedModelKey(spec, externalConfig)
	if err != nil {
		return err
	}

	if spec.VerifyEncryptedSHA256 {
		if err := verifyEncryptedDeviceSHA256(spec.Device, spec.EncryptedSHA256); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(boot.ModelKeyDir, 0700); err != nil {
		return fmt.Errorf("creating model key directory: %w", err)
	}
	keyFile := fmt.Sprintf("%s/%s.key", boot.ModelKeyDir, spec.RootHash)
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return fmt.Errorf("writing model key file: %w", err)
	}
	defer os.Remove(keyFile)

	cryptName := fmt.Sprintf("empk-%s-crypt", spec.RootHash)
	verityName := fmt.Sprintf("mpk-%s", spec.RootHash)
	mountPoint := fmt.Sprintf("%s/%s", boot.MPKDir, verityName)

	log.Printf("Opening encrypted model pack %s (device=%s)", modelLogName(name, spec.RootHash), spec.Device)
	cryptCmd := exec.Command(
		"cryptsetup", "open",
		"--type", "plain",
		"--cipher", encryptedModelCipher(spec),
		"--key-size", strconv.Itoa(encryptedModelKeySize(spec)),
		"--sector-size", strconv.Itoa(encryptedModelSectorSize(spec)),
		"--key-file", keyFile,
		spec.Device,
		cryptName,
	)
	cryptCmd.Stdout = os.Stdout
	cryptCmd.Stderr = os.Stderr
	if err := cryptCmd.Run(); err != nil {
		return fmt.Errorf("cryptsetup open: %w", err)
	}

	cryptDevice := "/dev/mapper/" + cryptName
	verityArgs := []string{
		"open",
		cryptDevice,
		verityName,
		cryptDevice,
		spec.RootHash,
		"--hash-offset=" + spec.HashOffset,
	}
	if spec.DataBlockSize != 0 {
		verityArgs = append(verityArgs, "--data-block-size="+strconv.Itoa(spec.DataBlockSize))
	}
	if spec.HashBlockSize != 0 {
		verityArgs = append(verityArgs, "--hash-block-size="+strconv.Itoa(spec.HashBlockSize))
	}
	if spec.DataBlocks != "" {
		verityArgs = append(verityArgs, "--data-blocks="+spec.DataBlocks)
	}

	verityCmd := exec.Command("veritysetup", verityArgs...)
	verityCmd.Stdout = os.Stdout
	verityCmd.Stderr = os.Stderr
	if err := verityCmd.Run(); err != nil {
		_ = exec.Command("cryptsetup", "close", cryptName).Run()
		return fmt.Errorf("veritysetup open: %w", err)
	}

	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		_ = exec.Command("veritysetup", "close", verityName).Run()
		_ = exec.Command("cryptsetup", "close", cryptName).Run()
		return fmt.Errorf("creating mount point: %w", err)
	}

	mountCmd := exec.Command(
		"mount", "-o", "ro",
		"/dev/mapper/"+verityName,
		mountPoint,
	)
	mountCmd.Stdout = os.Stdout
	mountCmd.Stderr = os.Stderr
	if err := mountCmd.Run(); err != nil {
		_ = exec.Command("veritysetup", "close", verityName).Run()
		_ = exec.Command("cryptsetup", "close", cryptName).Run()
		return fmt.Errorf("mounting verity device: %w", err)
	}

	log.Printf("Mounted encrypted model pack %s at %s", modelLogName(name, spec.RootHash), mountPoint)
	return nil
}

func validateEncryptedModelPack(spec *EncryptedModelPackSpec) error {
	if spec == nil {
		return fmt.Errorf("missing empk spec")
	}
	if !devicePathPattern.MatchString(spec.Device) {
		return fmt.Errorf("invalid encrypted model device path: %s", spec.Device)
	}
	if !hexHashPattern.MatchString(spec.RootHash) {
		return fmt.Errorf("invalid root hash format: %s", spec.RootHash)
	}
	if !offsetPattern.MatchString(spec.HashOffset) {
		return fmt.Errorf("invalid hash offset format: %s", spec.HashOffset)
	}
	if spec.UUID != "" && !uuidPattern.MatchString(spec.UUID) {
		return fmt.Errorf("invalid UUID format: %s", spec.UUID)
	}
	if !secretNamePattern.MatchString(spec.KeySecret) {
		return fmt.Errorf("invalid key secret name: %s", spec.KeySecret)
	}
	if cipher := encryptedModelCipher(spec); cipher != defaultEMPKCipher {
		return fmt.Errorf("unsupported encrypted model cipher: %s", cipher)
	}
	if keySize := encryptedModelKeySize(spec); keySize != defaultEMPKKeySize {
		return fmt.Errorf("unsupported encrypted model key size: %d", keySize)
	}
	if sectorSize := encryptedModelSectorSize(spec); sectorSize != defaultEMPKSectorSize {
		return fmt.Errorf("unsupported encrypted model sector size: %d", sectorSize)
	}
	if spec.EncryptedSHA256 != "" && !hexHashPattern.MatchString(spec.EncryptedSHA256) {
		return fmt.Errorf("invalid encrypted image sha256 format: %s", spec.EncryptedSHA256)
	}
	if spec.VerifyEncryptedSHA256 && spec.EncryptedSHA256 == "" {
		return fmt.Errorf("verify-encrypted-sha256 requires encrypted-sha256")
	}
	if spec.DataBlockSize != 0 && spec.DataBlockSize != 4096 {
		return fmt.Errorf("unsupported dm-verity data block size: %d", spec.DataBlockSize)
	}
	if spec.HashBlockSize != 0 && spec.HashBlockSize != 4096 {
		return fmt.Errorf("unsupported dm-verity hash block size: %d", spec.HashBlockSize)
	}
	if spec.DataBlocks != "" && !offsetPattern.MatchString(spec.DataBlocks) {
		return fmt.Errorf("invalid dm-verity data blocks format: %s", spec.DataBlocks)
	}
	return nil
}

func encryptedModelKey(spec *EncryptedModelPackSpec, externalConfig *shimconfig.ExternalConfig) ([]byte, error) {
	if externalConfig == nil {
		return nil, fmt.Errorf("external config is required for encrypted model key %q", spec.KeySecret)
	}
	secret := externalConfig.GetSecret(spec.KeySecret)
	if secret == "" {
		return nil, fmt.Errorf("encrypted model key secret %q not found", spec.KeySecret)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted model key secret %q as base64: %w", spec.KeySecret, err)
	}
	if len(key) != defaultEMPKKeySize/8 {
		return nil, fmt.Errorf("encrypted model key secret %q decoded to %d bytes, want %d", spec.KeySecret, len(key), defaultEMPKKeySize/8)
	}
	return key, nil
}

func verifyEncryptedDeviceSHA256(device, expected string) error {
	f, err := os.Open(device)
	if err != nil {
		return fmt.Errorf("opening encrypted model device for sha256: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hashing encrypted model device: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("encrypted model device sha256 mismatch: got %s want %s", actual, expected)
	}
	return nil
}

func encryptedModelCipher(spec *EncryptedModelPackSpec) string {
	if spec.Cipher == "" {
		return defaultEMPKCipher
	}
	return spec.Cipher
}

func encryptedModelKeySize(spec *EncryptedModelPackSpec) int {
	if spec.KeySize == 0 {
		return defaultEMPKKeySize
	}
	return spec.KeySize
}

func encryptedModelSectorSize(spec *EncryptedModelPackSpec) int {
	if spec.SectorSize == 0 {
		return defaultEMPKSectorSize
	}
	return spec.SectorSize
}

func modelLogName(name, rootHash string) string {
	if name != "" {
		return name
	}
	return "mpk-" + rootHash
}
