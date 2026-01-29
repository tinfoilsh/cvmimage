package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// mountModels mounts all model packs from the config
func mountModels(config *Config) error {
	if len(config.Models) == 0 {
		log.Println("No models to mount")
		return nil
	}

	log.Printf("Mounting %d model packs", len(config.Models))
	for _, model := range config.Models {
		if err := mountModelPack(model.MPK); err != nil {
			return fmt.Errorf("mounting model pack %s: %w", model.MPK, err)
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
	mountPoint := fmt.Sprintf("/mnt/ramdisk/mpk/%s", deviceName)

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
