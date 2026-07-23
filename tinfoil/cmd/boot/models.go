package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/tinfoilsh/modelwrap"
	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/device"
	"tinfoil/internal/devicemapper"
)

const (
	veritySuperblockSize = 512
	veritySaltSize       = 32
	sectorSize           = 512
)

// mountModels mounts all model packs from the config
func mountModels(config *Config, externalConfig *shimconfig.ExternalConfig) error {
	if len(config.Models) == 0 {
		log.Println("No models to mount")
		return nil
	}

	log.Printf("Mounting %d model packs", len(config.Models))
	seen := map[string]struct{}{}
	for index, model := range config.Models {
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
			sourceDevice, err := device.ModelDisk(index)
			if err != nil {
				return fmt.Errorf("finding model disk %d: %w", index, err)
			}
			if err := mountModelPack(ref, sourceDevice); err != nil {
				return fmt.Errorf("mounting model pack %s: %w", ref.raw, err)
			}
		case modelKindEncrypted:
			sourceDevice, err := device.ModelPartition(index, device.EMWPPayloadPartition)
			if err != nil {
				return fmt.Errorf("finding encrypted model partition %d: %w", index, err)
			}
			if err := mountEncryptedModelPack(model, externalConfig, sourceDevice); err != nil {
				return fmt.Errorf("mounting encrypted model pack %q: %w", model.Name, err)
			}
		}
	}

	return nil
}

// mountModelPack mounts a plaintext model wrap using dm-verity.
func mountModelPack(spec *modelPackRef, sourceDevice string) error {
	deviceName := spec.mapperName()
	mountPoint := spec.mountPoint()

	log.Printf("Opening verity device %s (uuid=%s)", deviceName, spec.UUID)
	if err := createLegacyModelPackAlias(spec); err != nil {
		return err
	}
	if err := openAndMountVerity(sourceDevice, deviceName, spec.RootHash, spec.HashOffset, mountPoint); err != nil {
		removeLegacyModelPackAlias(spec)
		return err
	}

	log.Printf("Mounted model pack %s at %s", deviceName, mountPoint)
	return nil
}

// mountEncryptedModelPack mounts an encrypted model wrap using dm-crypt below
// dm-verity. The decrypted mapper contains the same plaintext layout as an MWP:
// a read-only filesystem followed by its dm-verity hash tree.
func mountEncryptedModelPack(
	model ModelSpec,
	externalConfig *shimconfig.ExternalConfig,
	sourceDevice string,
) error {
	spec, err := parseModelPackRef(model.EMWP)
	if err != nil {
		return fmt.Errorf("invalid EMWP format: %s: %w", model.EMWP, err)
	}

	key, err := encryptedModelKey(model.KeySecret, spec, externalConfig)
	if err != nil {
		return err
	}
	defer zeroBytes(key)

	cryptName := fmt.Sprintf("emwp-%s-crypt", spec.RootHash)
	verityName := spec.mapperName()
	mountPoint := spec.mountPoint()

	log.Printf("Opening encrypted model pack %s (uuid=%s)", modelLogName(model.Name, spec.RootHash), spec.UUID)
	if err := createLegacyModelPackAlias(spec); err != nil {
		return err
	}
	if err := openEncryptedAndMount(
		directModelVolumeOps{},
		sourceDevice,
		cryptName,
		verityName,
		spec.RootHash,
		spec.HashOffset,
		mountPoint,
		key,
	); err != nil {
		removeLegacyModelPackAlias(spec)
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
	defer zeroBytes(key)
	return modelwrap.DeriveKey(key, spec.ArtifactRef)
}

func openAndMountVerity(sourceDevice, deviceName, rootHash, hashOffset, mountPoint string) error {
	return openAndMountVerityWithOps(directModelVolumeOps{}, sourceDevice, deviceName, rootHash, hashOffset, mountPoint)
}

type modelVolumeOps interface {
	openVerity(sourceDevice, name, rootHash, hashOffset string) (string, error)
	openCrypt(sourceDevice, name string, key []byte) (string, error)
	remove(name string) error
	mount(sourceDevice, mountPoint string) error
}

type directModelVolumeOps struct{}

func (directModelVolumeOps) openVerity(sourceDevice, name, rootHash, hashOffset string) (string, error) {
	offset, err := strconv.ParseUint(hashOffset, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid verity hash offset %q: %w", hashOffset, err)
	}
	salt, err := readFixedVeritySalt(sourceDevice, offset)
	if err != nil {
		return "", err
	}
	lengthSectors, params, err := fixedVerityTable(sourceDevice, rootHash, offset, salt)
	zeroBytes(salt)
	if err != nil {
		return "", err
	}
	return activateReadOnlyMapping(name, lengthSectors, func(control *os.File) error {
		return devicemapper.LoadReadOnlyVerityTable(control, name, lengthSectors, params)
	})
}

func (directModelVolumeOps) openCrypt(sourceDevice, name string, key []byte) (string, error) {
	deviceNumber, err := devicemapper.BlockDeviceNumber(sourceDevice)
	if err != nil {
		return "", err
	}
	lengthSectors, err := devicemapper.BlockDeviceSectors(sourceDevice)
	if err != nil {
		return "", err
	}
	params, err := devicemapper.CryptTable(deviceNumber, modelwrap.EMWPCipher, key, modelwrap.EMWPSectorSize, lengthSectors)
	if err != nil {
		return "", err
	}
	defer zeroBytes(params)
	return activateReadOnlyMapping(name, lengthSectors, func(control *os.File) error {
		return devicemapper.LoadReadOnlyCryptTable(control, name, lengthSectors, params)
	})
}

func (directModelVolumeOps) remove(name string) error {
	control, err := devicemapper.OpenControl()
	if err != nil {
		return err
	}
	defer control.Close()
	return devicemapper.Remove(control, name)
}

func (directModelVolumeOps) mount(sourceDevice, mountPoint string) error {
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("creating model mount point: %w", err)
	}
	if err := unix.Mount(
		sourceDevice,
		mountPoint,
		"erofs",
		unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC,
		"",
	); err != nil {
		return fmt.Errorf("mounting verified model volume: %w", err)
	}
	return nil
}

func openAndMountVerityWithOps(
	ops modelVolumeOps,
	sourceDevice, deviceName, rootHash, hashOffset, mountPoint string,
) error {
	mapperNode, err := ops.openVerity(sourceDevice, deviceName, rootHash, hashOffset)
	if err != nil {
		return err
	}
	if err := ops.mount(mapperNode, mountPoint); err != nil {
		if removeErr := ops.remove(deviceName); removeErr != nil {
			return errors.Join(err, fmt.Errorf("removing failed verity mapping: %w", removeErr))
		}
		return err
	}
	return nil
}

func openEncryptedAndMount(
	ops modelVolumeOps,
	sourceDevice, cryptName, verityName, rootHash, hashOffset, mountPoint string,
	key []byte,
) error {
	defer zeroBytes(key)
	cryptDevice, err := ops.openCrypt(sourceDevice, cryptName, key)
	if err != nil {
		return err
	}
	if err := openAndMountVerityWithOps(ops, cryptDevice, verityName, rootHash, hashOffset, mountPoint); err != nil {
		if removeErr := ops.remove(cryptName); removeErr != nil {
			return errors.Join(err, fmt.Errorf("removing failed crypt mapping: %w", removeErr))
		}
		return err
	}
	return nil
}

func activateReadOnlyMapping(
	name string,
	lengthSectors uint64,
	load func(control *os.File) error,
) (mapperNode string, returnErr error) {
	control, err := devicemapper.OpenControl()
	if err != nil {
		return "", err
	}
	defer control.Close()
	if _, err := devicemapper.CheckVersion(control); err != nil {
		return "", err
	}
	if _, err := devicemapper.CreateReadOnly(control, name); err != nil {
		return "", err
	}
	defer func() {
		if returnErr != nil {
			if err := devicemapper.Remove(control, name); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("removing incomplete mapping: %w", err))
			}
		}
	}()
	if err := load(control); err != nil {
		return "", err
	}
	if err := devicemapper.ResumeReadOnly(control, name); err != nil {
		return "", err
	}
	info, err := devicemapper.Status(control, name)
	if err != nil {
		return "", err
	}
	if !info.Active() || !info.ReadOnly() || info.TargetCount != 1 {
		return "", fmt.Errorf("mapping %s has unexpected state: active=%t read-only=%t targets=%d", name, info.Active(), info.ReadOnly(), info.TargetCount)
	}
	mapperNode = devicemapper.MapperNode(name)
	if err := devicemapper.EnsureBlockNode(mapperNode, info.Dev); err != nil {
		return "", err
	}
	return mapperNode, nil
}

func fixedVerityTable(sourceDevice, rootHash string, hashOffset uint64, salt []byte) (uint64, string, error) {
	if hashOffset == 0 || hashOffset%modelwrap.VerityDataBlockSize != 0 {
		return 0, "", fmt.Errorf("verity hash offset %d is not a positive multiple of %d", hashOffset, modelwrap.VerityDataBlockSize)
	}
	if len(salt) != veritySaltSize {
		return 0, "", fmt.Errorf("verity salt is %d bytes, want %d", len(salt), veritySaltSize)
	}
	deviceNumber, err := devicemapper.BlockDeviceNumber(sourceDevice)
	if err != nil {
		return 0, "", err
	}
	return verityTable(deviceNumber, rootHash, hashOffset, salt)
}

func verityTable(deviceNumber, rootHash string, hashOffset uint64, salt []byte) (uint64, string, error) {
	if deviceNumber == "" || strings.ContainsAny(deviceNumber, " \t\r\n\x00") {
		return 0, "", fmt.Errorf("invalid verity device number %q", deviceNumber)
	}
	if hashOffset == 0 || hashOffset%modelwrap.VerityDataBlockSize != 0 {
		return 0, "", fmt.Errorf("verity hash offset %d is not a positive multiple of %d", hashOffset, modelwrap.VerityDataBlockSize)
	}
	if len(salt) != veritySaltSize {
		return 0, "", fmt.Errorf("verity salt is %d bytes, want %d", len(salt), veritySaltSize)
	}
	decodedRootHash, err := hex.DecodeString(rootHash)
	if err != nil || len(decodedRootHash) != 32 {
		return 0, "", fmt.Errorf("invalid verity root hash")
	}
	zeroBytes(decodedRootHash)
	if hashOffset > uint64(1<<63-modelwrap.VerityHashBlockSize) {
		return 0, "", fmt.Errorf("verity hash offset %d exceeds supported maximum", hashOffset)
	}
	dataBlocks := hashOffset / modelwrap.VerityDataBlockSize
	hashStartBlock := dataBlocks + 1
	lengthSectors := hashOffset / sectorSize
	params := fmt.Sprintf(
		"1 %s %s %d %d %d %d %s %s %s",
		deviceNumber,
		deviceNumber,
		modelwrap.VerityDataBlockSize,
		modelwrap.VerityHashBlockSize,
		dataBlocks,
		hashStartBlock,
		modelwrap.VerityHashAlgorithm,
		rootHash,
		hex.EncodeToString(salt),
	)
	return lengthSectors, params, nil
}

func readFixedVeritySalt(sourceDevice string, hashOffset uint64) ([]byte, error) {
	if hashOffset == 0 || hashOffset%modelwrap.VerityDataBlockSize != 0 {
		return nil, fmt.Errorf("verity hash offset %d is not a positive multiple of %d", hashOffset, modelwrap.VerityDataBlockSize)
	}
	if hashOffset > uint64(1<<63-modelwrap.VerityHashBlockSize) {
		return nil, fmt.Errorf("verity hash offset %d exceeds supported file offset", hashOffset)
	}
	file, err := os.Open(sourceDevice)
	if err != nil {
		return nil, fmt.Errorf("opening verity device %s: %w", sourceDevice, err)
	}
	defer file.Close()
	superblock := make([]byte, veritySuperblockSize)
	if _, err := file.ReadAt(superblock, int64(hashOffset)); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("reading fixed verity header: short read")
		}
		return nil, fmt.Errorf("reading fixed verity header: %w", err)
	}
	if string(superblock[0:8]) != "verity\x00\x00" ||
		binary.LittleEndian.Uint32(superblock[8:12]) != modelwrap.VerityFormat ||
		binary.LittleEndian.Uint32(superblock[12:16]) != 1 ||
		strings.TrimRight(string(superblock[32:64]), "\x00") != modelwrap.VerityHashAlgorithm ||
		binary.LittleEndian.Uint32(superblock[64:68]) != modelwrap.VerityDataBlockSize ||
		binary.LittleEndian.Uint32(superblock[68:72]) != modelwrap.VerityHashBlockSize ||
		binary.LittleEndian.Uint64(superblock[72:80]) != hashOffset/modelwrap.VerityDataBlockSize ||
		binary.LittleEndian.Uint16(superblock[80:82]) != veritySaltSize {
		zeroBytes(superblock)
		return nil, fmt.Errorf("verity header does not match the fixed modelwrap contract")
	}
	salt := append([]byte(nil), superblock[88:88+veritySaltSize]...)
	zeroBytes(superblock)
	return salt, nil
}

func zeroBytes(buf []byte) {
	for index := range buf {
		buf[index] = 0
	}
}

func modelLogName(name, rootHash string) string {
	if name != "" {
		return name
	}
	return "mwp-" + rootHash
}
