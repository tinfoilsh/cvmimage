package main

import (
	"fmt"
	"log"
	"os"

	"github.com/tinfoilsh/modelwrap"
	"github.com/tinfoilsh/modelwrap/unwrap"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// mountModels mounts all model packs from the config
func mountModels(config *Config, externalConfig *shimconfig.ExternalConfig) error {
	if len(config.Models) == 0 {
		log.Println("No models to mount")
		return nil
	}

	log.Printf("Mounting %d model packs", len(config.Models))
	seen := map[string]struct{}{}
	for _, model := range config.Models {
		ref, kind, err := modelPackRefForModel(model)
		if err != nil {
			return err
		}
		if _, ok := seen[ref.mapperName()]; ok {
			return fmt.Errorf("duplicate model pack root hash: %s", ref.RootHash)
		}
		seen[ref.mapperName()] = struct{}{}

		switch kind {
		case modelKindPlaintext:
			if err := mountModelPack(ref); err != nil {
				return fmt.Errorf("mounting model pack %s: %w", ref.raw, err)
			}
		case modelKindEncrypted:
			if err := mountEncryptedModelPack(model, externalConfig); err != nil {
				return fmt.Errorf("mounting encrypted model pack %q: %w", model.Name, err)
			}
		}
	}

	return nil
}

// mountModelPack mounts a plaintext model wrap using dm-verity.
func mountModelPack(spec *modelPackRef) error {
	deviceName := spec.mapperName()
	mountPoint := spec.mountPoint()

	log.Printf("Opening verity device %s (uuid=%s)", deviceName, spec.UUID)
	if err := createLegacyModelPackAlias(spec); err != nil {
		return err
	}
	if err := openAndMountVerity(diskByUUID(spec.UUID), deviceName, spec.RootHash, spec.HashOffset, mountPoint); err != nil {
		removeLegacyModelPackAlias(spec)
		return err
	}

	log.Printf("Mounted model pack %s at %s", deviceName, mountPoint)
	return nil
}

// mountEncryptedModelPack mounts an encrypted model wrap using dm-crypt below
// dm-verity. The decrypted mapper contains the same plaintext layout as an MWP:
// a read-only filesystem followed by its dm-verity hash tree.
func mountEncryptedModelPack(model ModelSpec, externalConfig *shimconfig.ExternalConfig) error {
	spec, err := parseModelPackRef(model.EMWP)
	if err != nil {
		return fmt.Errorf("invalid EMWP format: %s: %w", model.EMWP, err)
	}

	key, err := encryptedModelKey(model.KeySecret, spec, externalConfig)
	if err != nil {
		return err
	}

	keyFile, err := writePersistentModelKey(spec, key)
	if err != nil {
		return err
	}

	cryptName := fmt.Sprintf("emwp-%s-crypt", spec.RootHash)
	verityName := spec.mapperName()
	mountPoint := spec.mountPoint()

	log.Printf("Opening encrypted model pack %s (uuid=%s)", modelLogName(model.Name, spec.RootHash), spec.UUID)
	if err := createLegacyModelPackAlias(spec); err != nil {
		return err
	}
	if err := unwrap.OpenCrypt(diskByPARTUUID(spec.UUID), cryptName, keyFile); err != nil {
		removeLegacyModelPackAlias(spec)
		return err
	}

	cryptDevice := "/dev/mapper/" + cryptName
	if err := openAndMountVerity(cryptDevice, verityName, spec.RootHash, spec.HashOffset, mountPoint); err != nil {
		removeLegacyModelPackAlias(spec)
		unwrap.CloseCrypt(cryptName)
		return err
	}

	log.Printf("Mounted encrypted model pack %s at %s", modelLogName(model.Name, spec.RootHash), mountPoint)
	return nil
}

func createLegacyModelPackAlias(spec *modelPackRef) error {
	if err := os.MkdirAll(boot.MPKDir, 0755); err != nil {
		return fmt.Errorf("creating legacy model pack alias directory: %w", err)
	}
	aliasPath := spec.legacyMountPoint()
	if fi, err := os.Lstat(aliasPath); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("legacy model pack alias path exists and is not a symlink: %s", aliasPath)
		}
		if err := os.Remove(aliasPath); err != nil {
			return fmt.Errorf("removing stale legacy model pack alias: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking legacy model pack alias: %w", err)
	}
	if err := os.Symlink("../mwp/"+spec.mapperName(), aliasPath); err != nil {
		return fmt.Errorf("creating legacy model pack alias: %w", err)
	}
	return nil
}

func removeLegacyModelPackAlias(spec *modelPackRef) {
	_ = os.Remove(spec.legacyMountPoint())
}

func writePersistentModelKey(spec *modelPackRef, key []byte) (string, error) {
	if err := os.MkdirAll(boot.ModelKeyDir, 0700); err != nil {
		return "", fmt.Errorf("creating model key directory: %w", err)
	}
	if err := os.Chmod(boot.ModelKeyDir, 0700); err != nil {
		return "", fmt.Errorf("setting model key directory permissions: %w", err)
	}
	keyFile := fmt.Sprintf("%s/%s.key", boot.ModelKeyDir, spec.ArtifactID())
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return "", fmt.Errorf("writing model key file: %w", err)
	}
	if err := os.Chmod(keyFile, 0600); err != nil {
		return "", fmt.Errorf("setting model key file permissions: %w", err)
	}
	return keyFile, nil
}

type modelKind string

const (
	modelKindPlaintext modelKind = "plaintext"
	modelKindEncrypted modelKind = "encrypted"
)

func modelPackRefForModel(model ModelSpec) (*modelPackRef, modelKind, error) {
	refs := 0
	if model.MPK != "" {
		refs++
	}
	if model.MWP != "" {
		refs++
	}
	if model.EMWP != "" {
		refs++
	}
	if refs != 1 {
		return nil, "", fmt.Errorf("model %q must specify exactly one of mpk, mwp, or emwp", model.Name)
	}

	if model.MPK != "" {
		spec, err := parseModelPackRef(model.MPK)
		if err != nil {
			return nil, "", fmt.Errorf("invalid legacy MPK format: %s: %w", model.MPK, err)
		}
		return spec, modelKindPlaintext, nil
	}
	if model.MWP != "" {
		spec, err := parseModelPackRef(model.MWP)
		if err != nil {
			return nil, "", fmt.Errorf("invalid MWP format: %s: %w", model.MWP, err)
		}
		return spec, modelKindPlaintext, nil
	}

	spec, err := parseModelPackRef(model.EMWP)
	if err != nil {
		return nil, "", fmt.Errorf("invalid EMWP format: %s: %w", model.EMWP, err)
	}
	return spec, modelKindEncrypted, nil
}

// modelPackRef wraps the shared artifact reference with cvmimage mount
// layout policy (mapper names, mount points, legacy aliases).
type modelPackRef struct {
	*modelwrap.ArtifactRef
	raw string
}

func (r *modelPackRef) mapperName() string {
	return "mwp-" + r.RootHash
}

func (r *modelPackRef) mountPoint() string {
	return boot.MWPDir + "/" + r.mapperName()
}

func (r *modelPackRef) legacyMountPoint() string {
	return boot.MPKDir + "/mpk-" + r.RootHash
}

func parseModelPackRef(ref string) (*modelPackRef, error) {
	parsed, err := modelwrap.ParseRef(ref)
	if err != nil {
		return nil, err
	}
	return &modelPackRef{ArtifactRef: parsed, raw: ref}, nil
}

func encryptedModelKey(keySecret string, spec *modelPackRef, externalConfig *shimconfig.ExternalConfig) ([]byte, error) {
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
	key, err := modelwrap.ParseMasterKey(secret)
	if err != nil {
		return nil, fmt.Errorf("encrypted model key secret %q: %w", keySecret, err)
	}
	return modelwrap.DeriveKey(key, spec.ArtifactRef)
}

func openAndMountVerity(sourceDevice, deviceName, rootHash, hashOffset, mountPoint string) error {
	if err := unwrap.OpenVerity(sourceDevice, deviceName, rootHash, hashOffset); err != nil {
		return err
	}
	if err := unwrap.Mount("/dev/mapper/"+deviceName, mountPoint); err != nil {
		unwrap.CloseVerity(deviceName)
		return err
	}
	return nil
}

func diskByUUID(uuid string) string {
	return fmt.Sprintf("/dev/disk/by-uuid/%s", uuid)
}

func diskByPARTUUID(uuid string) string {
	return fmt.Sprintf("/dev/disk/by-partuuid/%s", uuid)
}

func modelLogName(name, rootHash string) string {
	if name != "" {
		return name
	}
	return "mwp-" + rootHash
}
