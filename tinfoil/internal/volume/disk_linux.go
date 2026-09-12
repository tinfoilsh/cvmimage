package volume

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"golang.org/x/sys/unix"

	"tinfoil/internal/devicemapper"
)

const (
	mapperRoot = "tinfoil-volume-"
	maxOwner   = 65534

	integritySuffix = "-integrity"

	// A request carries one key, but the table needs a cipher key and a MAC key.
	tableKeyInfo = "tinfoil volume table key v1"

	blankProbeSize = 1 << 20
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// diskDevice owns an authenticated disk's crypt and integrity mappings.
type diskDevice struct {
	crypt, integrity *devicemapper.Mapping
}

func (d *diskDevice) Path() string         { return d.crypt.Path() }
func (d *diskDevice) DeviceNumber() uint64 { return d.crypt.DeviceNumber() }

func (d *diskDevice) Close() error {
	if d == nil {
		return nil
	}
	if d.crypt != nil {
		if err := d.crypt.Close(); err != nil {
			return err
		}
		d.crypt = nil
	}
	if d.integrity != nil {
		if err := d.integrity.Close(); err != nil {
			return err
		}
		d.integrity = nil
	}
	return nil
}

// openDisk opens the mappings and reports whether this is a new disk to format.
// Initialization policy is checked before creating an integrity superblock.
// The caller must close any returned handle, even on partial failure.
func openDisk(sourcePath, name, access string, spec DiskSource, key []byte) (*diskDevice, bool, error) {
	control, err := devicemapper.OpenControl()
	if err != nil {
		return nil, false, err
	}
	defer control.Close()
	if _, err := devicemapper.CheckVersion(control); err != nil {
		return nil, false, err
	}
	source, err := devicemapper.OpenBlockDevice(sourcePath)
	if err != nil {
		return nil, false, err
	}
	defer source.Close()
	readOnly := access == "ro"
	if readOnly {
		// Also prevent lower integrity journal recovery from writing the source.
		if err := unix.IoctlSetPointerInt(int(source.Fd()), unix.BLKROSET, 1); err != nil {
			return nil, false, err
		}
	}
	blank, err := blockDeviceBlank(source)
	if err != nil {
		return nil, false, err
	}
	if blank && spec.Initialize != "if-empty" {
		return nil, false, errors.New("volume is uninitialized and initialization is disabled")
	}
	tableKey, err := hkdf.Key(sha256.New, key, nil, tableKeyInfo, devicemapper.AuthenticatedKeyBytes)
	if err != nil {
		return nil, false, err
	}
	defer clear(tableKey)
	mapperName := mapperRoot + name
	d := &diskDevice{}
	d.integrity, err = devicemapper.OpenIntegrity(control, source, mapperName+integritySuffix, blank, readOnly)
	if err != nil {
		return d, blank, err
	}
	tags, err := devicemapper.OpenBlockDevice(d.integrity.Path())
	if err != nil {
		return d, blank, err
	}
	defer tags.Close()
	d.crypt, err = devicemapper.OpenAuthenticatedCrypt(control, tags, mapperName, tableKey, readOnly)
	if err != nil {
		return d, blank, err
	}
	return d, blank, nil
}

func blockDeviceBlank(source *os.File) (bool, error) {
	// This device is attached to the VM after the guest has already booted, and
	// the kernel read sector 0 of it while enumerating it -- against the empty
	// backing that stood there until the attach. That page is still in the
	// block device's cache and reads as zeros, so a probe that trusted it could
	// call a workspace that has been in use blank, and the caller treats blank
	// as permission to reformat. BLKFLSBUF drops the cache, which is what makes
	// the read below see the volume that is actually attached now.
	if err := unix.IoctlSetInt(int(source.Fd()), unix.BLKFLSBUF, 0); err != nil {
		return false, fmt.Errorf("invalidating the stale block cache: %w", err)
	}
	buffer := make([]byte, blankProbeSize)
	defer clear(buffer)
	n, err := source.ReadAt(buffer, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if n == 0 {
		return false, errors.New("storage volume is empty")
	}
	for _, value := range buffer[:n] {
		if value != 0 {
			return false, nil
		}
	}
	return true, nil
}
