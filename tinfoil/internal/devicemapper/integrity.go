package devicemapper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	IntegrityKeyBytes      = sha256.Size
	integrityHeaderBytes   = 4096
	integrityHeaderSectors = integrityHeaderBytes / dmSectorSizeBytes
	integrityVersion       = 5
	// HAVE_JOURNAL_MAC | FIXED_PADDING | FIXED_HMAC. This is the only format;
	// no bitmap, recalculation, inline, or compatibility modes are supported.
	integrityFlags             = 0x19
	integrityInterleaveLog     = 15
	integrityInterleaveSectors = 1 << integrityInterleaveLog
	integrityBlockLog          = 3
	integrityMACOffset         = dmSectorSizeBytes - sha256.Size
	integrityBackingSuffix     = "-source"
	// Linux's journal has eight metadata sectors. Each entry stores an 8-byte
	// sector address, eight 8-byte displaced sector tails, and our 48-byte tag.
	// Four entries fit in a sector after the commit ID and journal MAC.
	integrityJournalSectionSectors = 8 + 8*4*8
	integrityMetadataSectors       = integrityTagBytes * (integrityInterleaveSectors / 8) / dmSectorSizeBytes
)

type integrityLayout struct {
	journalSectors  uint64
	journalSections uint32
	dataSectors     uint64
	bitmapLog       byte
}

// fixedIntegrityLayout mirrors Linux's interleaved J-mode geometry for the
// fixed 4096-byte/48-byte profile. No on-disk field participates in this
// calculation. Reported device size is still host input: bound it and keep
// the resulting composite device's size fixed for the lifetime of the mount.
func fixedIntegrityLayout(deviceSectors uint64) (integrityLayout, error) {
	if deviceSectors == 0 || deviceSectors > (1<<63-1)/dmSectorSizeBytes {
		return integrityLayout{}, errors.New("unsupported integrity device size")
	}
	l := integrityLayout{journalSectors: max(uint64(1), min(deviceSectors>>7, uint64(131072)))}
	l.journalSections = uint32(max(uint64(1), l.journalSectors/integrityJournalSectionSectors))
	initial := uint64(integrityHeaderSectors) + uint64(l.journalSections)*integrityJournalSectionSectors
	if deviceSectors <= initial+integrityMetadataSectors {
		return integrityLayout{}, errors.New("device is too small for the integrity profile")
	}
	remaining := deviceSectors - initial
	stride := uint64(integrityInterleaveSectors + integrityMetadataSectors)
	l.dataSectors = remaining / stride * integrityInterleaveSectors
	if tail := remaining % stride; tail > integrityMetadataSectors {
		l.dataSectors += tail - integrityMetadataSectors
	}
	l.dataSectors &^= 7
	if l.dataSectors == 0 {
		return integrityLayout{}, errors.New("integrity device has no usable blocks")
	}
	// The kernel records bitmap granularity even for J mode. It is normally
	// 12, but grows for very large devices; zero is not the canonical value.
	bitsInJournal := min(uint64(l.journalSections)*integrityJournalSectionSectors*4096, uint64(1<<32-1))
	log := uint8(15)
	for (l.dataSectors+(uint64(1)<<log)-1)>>log > bitsInJournal {
		log++
	}
	l.bitmapLog = log - integrityBlockLog
	return l, nil
}

// fixedIntegrityHeader builds the only supported superblock from Go policy,
// not from on-disk configuration. Only the 16-byte per-format salt is copied:
// the journal MAC uses it, so replacing it would invalidate the journal. The
// full constant-time comparison checks both the profile and its HMAC before
// returning the newly built bytes. There is no version negotiation, header
// repair, or unauthenticated fallback. Recovery/reserved bytes stay zero.
func fixedIntegrityHeader(snapshot, key []byte, layout integrityLayout) ([]byte, error) {
	if len(snapshot) != integrityHeaderBytes || len(key) != IntegrityKeyBytes {
		return nil, errors.New("invalid integrity header or metadata key length")
	}
	header := make([]byte, integrityHeaderBytes)
	copy(header[:8], integrityMagic)
	header[8] = integrityVersion
	header[9] = integrityInterleaveLog
	binary.LittleEndian.PutUint16(header[10:12], integrityTagBytes)
	binary.LittleEndian.PutUint32(header[12:16], layout.journalSections)
	binary.LittleEndian.PutUint64(header[16:24], layout.dataSectors)
	binary.LittleEndian.PutUint32(header[24:28], integrityFlags)
	header[28] = integrityBlockLog
	header[29] = layout.bitmapLog
	copy(header[48:64], snapshot[48:64])
	mac := hmac.New(sha256.New, key)
	mac.Write(header[:integrityMACOffset])
	copy(header[integrityMACOffset:dmSectorSizeBytes], mac.Sum(nil))
	if !hmac.Equal(snapshot, header) {
		return nil, errors.New("integrity superblock authentication or fixed-profile check failed")
	}
	return header, nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func integrityTable(deviceNumber string, key []byte, layout integrityLayout) ([]byte, error) {
	if !validDeviceNumber(deviceNumber) || len(key) != IntegrityKeyBytes {
		return nil, errors.New("invalid integrity device number or metadata key length")
	}
	params := []byte(fmt.Sprintf("%s 0 %d %s 9 block_size:%d fix_padding fix_hmac journal_sectors:%d interleave_sectors:%d buffer_sectors:128 journal_watermark:50 commit_time:10000 journal_mac:hmac(sha256):", deviceNumber, integrityTagBytes, integrityJournalMode, cryptSectorSizeBytes, layout.journalSectors, integrityInterleaveSectors))
	return hex.AppendEncode(params, key), nil
}

// ActivateIntegrity presents the fixed Go superblock to the kernel through a
// guest-private RAM-backed prefix. The raw disk supplies only the journal,
// tags and encrypted data. Constructor and resume reads cannot fetch header
// configuration from the raw disk. Formatting uses the stock kernel on a
// trusted zero prefix, with the same fixed profile checked before activation.
func ActivateIntegrity(control, source *os.File, name string, key []byte, initialize bool) (result error) {
	deviceNumber, deviceSectors, err := blockDeviceInfo(source)
	if err != nil {
		return err
	}
	if err := validateName(name + integrityBackingSuffix); err != nil {
		return err
	}
	if len(key) != IntegrityKeyBytes {
		return errors.New("invalid integrity metadata key length")
	}
	layout, err := fixedIntegrityLayout(deviceSectors)
	if err != nil {
		return err
	}
	if err := unix.IoctlSetInt(int(source.Fd()), unix.BLKFLSBUF, 0); err != nil {
		return fmt.Errorf("invalidating integrity superblock cache: %w", err)
	}
	header := make([]byte, integrityHeaderBytes)
	if _, err := source.ReadAt(header, 0); err != nil {
		return err
	}
	if initialize {
		if !allZero(header) {
			return errors.New("refusing to initialize a nonblank integrity superblock")
		}
	} else {
		header, err = fixedIntegrityHeader(header, key, layout)
		if err != nil {
			return err
		}
	}
	backing, err := newIntegrityBacking(control, name+integrityBackingSuffix, deviceNumber, deviceSectors, header)
	if err != nil {
		return err
	}
	integrityCreated := false
	defer func() {
		backing.source.Close()
		backing.header.Close()
		if result != nil {
			if integrityCreated {
				result = errors.Join(result, Remove(control, name))
			}
			result = errors.Join(result, Remove(control, name+integrityBackingSuffix))
		}
	}()
	backingNumber, _, err := blockDeviceInfo(backing.source)
	if err != nil {
		return err
	}
	params, err := integrityTable(backingNumber, key, layout)
	if err != nil {
		return err
	}
	defer clear(params)
	// Capacity is computed in Go, so both open and format need only one table
	// load. There is no probe mapping and no size read back from the disk header.
	if err := loadIntegrityTable(control, name, layout.dataSectors, params); err != nil {
		return err
	}
	integrityCreated = true
	if initialize {
		// Only the trusted zero prefix is formatted. The kernel creates the
		// salt, superblock MAC and initial journal using its stock implementation.
		if _, err := backing.header.ReadAt(header, 0); err != nil {
			return err
		}
		header, err = fixedIntegrityHeader(header, key, layout)
		if err != nil {
			return err
		}
		// The private prefix already exactly matches these Go-built bytes.
		// Persist the authenticated format for subsequent boots. Opening the
		// descriptor itself avoids resolving the raw device path again.
		raw, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", source.Fd()), os.O_WRONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		_, writeErr := raw.WriteAt(header, 0)
		result = errors.Join(writeErr, raw.Sync(), raw.Close())
		if result != nil {
			return result
		}
	}
	if err := resume(control, name, 0); err != nil {
		return err
	}
	info, err := Status(control, name)
	if err != nil {
		return err
	}
	if !info.Active() || info.ReadOnly() || info.TargetCount != 1 {
		return fmt.Errorf("integrity mapping %s has unexpected state", name)
	}
	return EnsureBlockNode(MapperNode(name), info.Dev)
}

func loadIntegrityTable(control *os.File, name string, lengthSectors uint64, params []byte) (result error) {
	if _, err := create(control, name, 0); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, Remove(control, name))
		}
	}()
	buf, err := tableLoadBufferBytes(name, lengthSectors, integrityTarget, params)
	if err != nil {
		return err
	}
	defer clear(buf)
	setFlags(buf, existsFlag|secureDataFlag)
	if err := ioctl(control, tableLoadIOCTL, buf, 1); err != nil {
		return fmt.Errorf("device-mapper integrity table load %s failed: %w", name, err)
	}
	return nil
}

// RemoveIntegrity removes the tag device and its private header mapping.
// The loop device uses autoclear and releases its anonymous tmpfs file when
// the final mapping reference closes, including after the volume worker exits.
func RemoveIntegrity(control *os.File, name string) error {
	// Remove may fail to unlink the node after deleting the kernel mapping.
	// Still try the backing; the kernel rejects removal if it remains in use.
	return errors.Join(Remove(control, name), Remove(control, name+integrityBackingSuffix))
}

func IntegrityBackingName(name string) string { return name + integrityBackingSuffix }
