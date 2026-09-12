package modelpack

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tinfoilsh/modelwrap"
	runtimeconfig "github.com/tinfoilsh/tinfoil-config"
	"tinfoil/internal/devicemapper"
)

const (
	veritySaltSize = 32
	sectorSize     = 512
)

// Source contains only the measured pack identity and protection mode.
type Source struct {
	Ref       string
	Repo      string
	Encrypted bool
}

// Compile resolves legacy reference spellings at the configuration boundary.
func Compile(model runtimeconfig.ModelSpec) (Source, error) {
	source := Source{Repo: model.Repo, Encrypted: model.EMWP != ""}
	refs := 0
	for _, ref := range []string{model.MPK, model.MWP, model.EMWP} {
		if ref != "" {
			source.Ref = ref
			refs++
		}
	}
	if refs != 1 {
		return Source{}, fmt.Errorf("model %q must specify exactly one of mpk, mwp, or emwp", model.Name)
	}
	return source, source.Validate()
}

func (s Source) Validate() error {
	if s.Repo == "" {
		return fmt.Errorf("pack requires a repo identity")
	}
	ref, err := modelwrap.ParseRef(s.Ref)
	if err != nil {
		return err
	}
	// Validate the verity layout without reading an untrusted device.
	offset, err := parseHashOffset(ref.HashOffset)
	if err != nil {
		return err
	}
	_, _, err = verityTable("0:0", ref.RootHash, offset, modelwrap.VeritySalt(s.Repo))
	return err
}

func (s Source) MapperName() string {
	ref, _ := modelwrap.ParseRef(s.Ref)
	if ref == nil {
		return ""
	}
	return "mwp-" + ref.RootHash
}

func fixedVerityTable(sourceDevice, rootHash string, hashOffset uint64, salt []byte) (uint64, string, error) {
	deviceNumber, _, err := devicemapper.BlockDeviceInfo(sourceDevice)
	if err != nil {
		return 0, "", err
	}
	return verityTable(deviceNumber, rootHash, hashOffset, salt)
}

func verityTable(deviceNumber, rootHash string, hashOffset uint64, salt []byte) (uint64, string, error) {
	if deviceNumber == "" || strings.ContainsAny(deviceNumber, " \t\r\n\x00") {
		return 0, "", fmt.Errorf("invalid verity device number %q", deviceNumber)
	}
	if err := validateVerityHashOffset(hashOffset); err != nil {
		return 0, "", err
	}
	if len(salt) != veritySaltSize {
		return 0, "", fmt.Errorf("verity salt is %d bytes, want %d", len(salt), veritySaltSize)
	}
	decodedRootHash, err := hex.DecodeString(rootHash)
	if err != nil || len(decodedRootHash) != 32 {
		return 0, "", fmt.Errorf("invalid verity root hash")
	}
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

func validateVerityHashOffset(hashOffset uint64) error {
	if hashOffset == 0 || hashOffset%modelwrap.VerityDataBlockSize != 0 {
		return fmt.Errorf("verity hash offset %d is not a positive multiple of %d", hashOffset, modelwrap.VerityDataBlockSize)
	}
	return nil
}
