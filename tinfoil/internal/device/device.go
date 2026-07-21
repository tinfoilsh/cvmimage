package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ConfigDiskSerial         = "tinfoil-config"
	ExternalConfigDiskSerial = "tinfoil-ext-config"
	ModelWrapSerialPrefix    = "tinfoil-modelwrap"

	filesystemProbeBytes = 4096
	uuidBytes            = 16
	maxQuotedIdentity    = 96
	// Shortest printable run treated as a candidate SCSI identity; below this
	// VPD fragments are noise rather than serials/wwids.
	minIdentityStringLength = 4

	erofsSuperOffset = 1024
	erofsMagic       = 0xE0F5E1E2
	erofsMagicOffset = erofsSuperOffset
	erofsUUIDOffset  = erofsSuperOffset + 0x30

	extSuperOffset = 1024
	extMagic       = 0xEF53
	extMagicOffset = extSuperOffset + 0x38
	extUUIDOffset  = extSuperOffset + 0x68
)

var (
	sysBlockDir = "/sys/block"
	devDir      = "/dev"
	groupFile   = "/etc/group"

	deviceWaitTimeout = 30 * time.Second
	deviceWaitDelay   = 100 * time.Millisecond
)

type scsiIdentity struct {
	source string
	value  string
}

// DiskBySCSISerial returns the devtmpfs node for a Tinfoil QEMU SCSI disk,
// polling for up to deviceWaitTimeout for the disk to appear.
func DiskBySCSISerial(serial string) (string, error) {
	return waitForDevice(func() (string, error) {
		return findDiskBySCSISerial(serial)
	})
}

// DiskBySCSISerialNoWait is DiskBySCSISerial without the polling wait, for
// optional disks (e.g. the external-config disk): absence is an expected
// outcome and must not stall boot for the full device timeout.
func DiskBySCSISerialNoWait(serial string) (string, error) {
	return findDiskBySCSISerial(serial)
}

// ModelDeviceByFilesystemUUID resolves plaintext modelwrap devices by reading
// fixed filesystem superblock UUID fields from disks in Tinfoil's modelwrap
// namespace. It intentionally avoids udev aliases and general-purpose probing.
func ModelDeviceByFilesystemUUID(uuid string) (string, error) {
	uuid = strings.ToLower(uuid)
	return waitForDevice(func() (string, error) {
		candidates, err := modelWrapBlockDevices()
		if err != nil {
			return "", err
		}
		for _, candidate := range candidates {
			found, err := filesystemUUID(candidate)
			if err != nil || found == "" {
				continue
			}
			if strings.ToLower(found) == uuid {
				return candidate, nil
			}
		}
		return "", fmt.Errorf("modelwrap filesystem UUID %s not found", uuid)
	})
}

// ModelDeviceByPARTUUID resolves encrypted modelwrap partition devices by
// reading partition metadata from sysfs instead of /dev/disk/by-partuuid.
func ModelDeviceByPARTUUID(partuuid string) (string, error) {
	partuuid = strings.ToLower(partuuid)
	return waitForDevice(func() (string, error) {
		candidates, err := modelWrapBlockDevices()
		if err != nil {
			return "", err
		}
		for _, candidate := range candidates {
			name := strings.TrimPrefix(candidate, devDir+"/")
			uevent, err := readUevent(filepath.Join(sysBlockDir, partitionSysfsPath(name), "uevent"))
			if err != nil || uevent["DEVTYPE"] != "partition" {
				continue
			}
			if strings.ToLower(uevent["PARTUUID"]) == partuuid {
				return candidate, nil
			}
		}
		return "", fmt.Errorf("modelwrap PARTUUID %s not found", partuuid)
	})
}

// SetupRequiredPermissions applies the small static permission policy that was
// previously expressed as udev rules.
func SetupRequiredPermissions() error {
	diskGID, err := groupID("disk")
	if err != nil {
		return err
	}
	videoGID, err := groupID("video")
	if err != nil {
		return err
	}
	renderGID, err := groupID("render")
	if err != nil {
		return err
	}

	var errs []error
	for _, path := range blockDeviceNodes() {
		errs = append(errs, chgrpMode(path, diskGID, 0660))
	}
	// nvidia-caps/* is deliberately absent: capability nodes keep the
	// stricter driver-requested DeviceFileMode (typically 0600) applied by
	// tinfoil-init instead of being widened to group video.
	for _, pattern := range []string{
		"nvidiactl",
		"nvidia-modeset",
		"nvidia-uvm",
		"nvidia-uvm-tools",
		"nvidia[0-9]*",
	} {
		for _, path := range globDev(pattern) {
			errs = append(errs, chgrpMode(path, videoGID, 0660))
		}
	}
	for _, path := range globDev("dri/card*") {
		errs = append(errs, chgrpMode(path, videoGID, 0660))
	}
	for _, pattern := range []string{"dri/renderD*", "accel/*"} {
		for _, path := range globDev(pattern) {
			errs = append(errs, chgrpMode(path, renderGID, 0660))
		}
	}

	return errors.Join(errs...)
}

func waitForDevice(find func() (string, error)) (string, error) {
	deadline := time.Now().Add(deviceWaitTimeout)
	var lastErr error
	for {
		path, err := find()
		if err == nil {
			return path, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return "", lastErr
		}
		time.Sleep(deviceWaitDelay)
	}
}

func findDiskBySCSISerial(serial string) (string, error) {
	entries, err := os.ReadDir(sysBlockDir)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", sysBlockDir, err)
	}
	for _, entry := range entries {
		if !isSCSIDisk(entry.Name()) {
			continue
		}
		ids, err := scsiIdentities(entry.Name())
		if err != nil || !identityMatchesSerial(ids, serial) {
			continue
		}
		path := filepath.Join(devDir, entry.Name())
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("device node for serial %s not ready at %s: %w", serial, path, err)
		}
		return path, nil
	}
	return "", fmt.Errorf("SCSI disk serial %s not found; candidates: %s", serial, describeSCSIDisks())
}

func modelWrapBlockDevices() ([]string, error) {
	entries, err := os.ReadDir(sysBlockDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", sysBlockDir, err)
	}
	var devices []string
	for _, entry := range entries {
		name := entry.Name()
		if !isSCSIDisk(name) {
			continue
		}
		ids, err := scsiIdentities(name)
		if err != nil || !identityTokenHasPrefix(ids, ModelWrapSerialPrefix) {
			continue
		}
		devices = appendDeviceIfReady(devices, name)

		partitions, err := filepath.Glob(filepath.Join(sysBlockDir, name, name+"*"))
		if err != nil {
			return nil, err
		}
		for _, partition := range partitions {
			uevent, err := readUevent(filepath.Join(partition, "uevent"))
			if err != nil || uevent["DEVTYPE"] != "partition" {
				continue
			}
			devices = appendDeviceIfReady(devices, uevent["DEVNAME"])
		}
	}
	sort.Strings(devices)
	if len(devices) == 0 {
		return nil, errors.New("no modelwrap SCSI disks found")
	}
	return devices, nil
}

func appendDeviceIfReady(devices []string, name string) []string {
	if name == "" {
		return devices
	}
	path := filepath.Join(devDir, name)
	if _, err := os.Stat(path); err == nil {
		return append(devices, path)
	}
	return devices
}

func partitionSysfsPath(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] < '0' || name[i] > '9' {
			if i == len(name)-1 {
				return name
			}
			return filepath.Join(name[:i+1], name)
		}
	}
	return name
}

func isSCSIDisk(name string) bool {
	if !strings.HasPrefix(name, "sd") {
		return false
	}
	_, err := os.Stat(filepath.Join(sysBlockDir, name, "device"))
	return err == nil
}

func scsiIdentities(name string) ([]scsiIdentity, error) {
	base := filepath.Join(sysBlockDir, name, "device")
	var ids []scsiIdentity
	var errs []error

	for _, source := range []string{"serial", "wwid"} {
		data, err := os.ReadFile(filepath.Join(base, source))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("%s: %w", source, err))
			}
			continue
		}
		ids = appendIdentity(ids, source, string(data))
	}

	if data, err := os.ReadFile(filepath.Join(base, "vpd_pg80")); err == nil {
		ids = appendIdentity(ids, "vpd_pg80", parseVPDPage80(data))
	} else if !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("vpd_pg80: %w", err))
	}

	if data, err := os.ReadFile(filepath.Join(base, "vpd_pg83")); err == nil {
		for _, id := range parseVPDPage83(data) {
			ids = appendIdentity(ids, "vpd_pg83", id)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("vpd_pg83: %w", err))
	}

	if len(ids) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("reading SCSI identity for %s: %w", name, errors.Join(errs...))
		}
		return nil, fmt.Errorf("no SCSI identity for %s", name)
	}
	return ids, nil
}

func appendIdentity(ids []scsiIdentity, source, value string) []scsiIdentity {
	value = trimIdentity(value)
	if value == "" {
		return ids
	}
	for _, id := range ids {
		if id.source == source && id.value == value {
			return ids
		}
	}
	return append(ids, scsiIdentity{source: source, value: value})
}

// SCSI identity sources embed the QEMU-assigned serial inside larger
// designators (e.g. wwid "t10.QEMU    QEMU HARDDISK    tinfoil-config"), so
// serials are compared against whitespace-delimited tokens of each identity
// value rather than by raw substring: substring matching would let a serial
// that embeds another Tinfoil serial select the wrong disk.
func identityMatchesSerial(ids []scsiIdentity, serial string) bool {
	for _, id := range ids {
		if id.value == serial {
			return true
		}
		for _, token := range strings.Fields(id.value) {
			if token == serial {
				return true
			}
		}
	}
	return false
}

// identityTokenHasPrefix reports whether any whitespace-delimited token of an
// identity value starts with prefix. Used for the modelwrap serial namespace
// (serials like "tinfoil-modelwrap-<n>").
func identityTokenHasPrefix(ids []scsiIdentity, prefix string) bool {
	for _, id := range ids {
		for _, token := range strings.Fields(id.value) {
			if strings.HasPrefix(token, prefix) {
				return true
			}
		}
	}
	return false
}

func parseVPDPage80(data []byte) string {
	if len(data) < 4 || data[1] != 0x80 {
		return ""
	}
	length := int(data[3])
	if 4+length <= len(data) {
		data = data[4 : 4+length]
	} else {
		data = data[4:]
	}
	return strings.TrimSpace(string(bytes.Trim(data, "\x00")))
}

func parseVPDPage83(data []byte) []string {
	if len(data) < 4 || data[1] != 0x83 {
		return nil
	}
	length := int(data[2])<<8 | int(data[3])
	end := 4 + length
	if end > len(data) {
		end = len(data)
	}

	var out []string
	for offset := 4; offset+4 <= end; {
		codeSet := data[offset] & 0x0f
		designatorLength := int(data[offset+3])
		next := offset + 4 + designatorLength
		if designatorLength == 0 || next > end {
			break
		}
		payload := data[offset+4 : next]
		if codeSet == 2 || codeSet == 3 {
			out = appendIdentityValue(out, string(payload))
		}
		for _, s := range printableStrings(payload) {
			out = appendIdentityValue(out, s)
		}
		offset = next
	}
	for _, s := range printableStrings(data[4:end]) {
		out = appendIdentityValue(out, s)
	}
	return out
}

func appendIdentityValue(values []string, value string) []string {
	value = trimIdentity(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func trimIdentity(value string) string {
	return strings.TrimSpace(string(bytes.Trim([]byte(value), "\x00")))
}

func printableStrings(data []byte) []string {
	var out []string
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start == -1 {
				start = i
			}
			continue
		}
		if start != -1 {
			out = appendPrintableString(out, data[start:i])
			start = -1
		}
	}
	if start != -1 {
		out = appendPrintableString(out, data[start:])
	}
	return out
}

func appendPrintableString(values []string, data []byte) []string {
	if len(data) < minIdentityStringLength {
		return values
	}
	return appendIdentityValue(values, string(data))
}

func describeSCSIDisks() string {
	entries, err := os.ReadDir(sysBlockDir)
	if err != nil {
		return fmt.Sprintf("unable to read %s: %v", sysBlockDir, err)
	}
	var summaries []string
	for _, entry := range entries {
		name := entry.Name()
		if !isSCSIDisk(name) {
			continue
		}
		var fields []string
		if ids, err := scsiIdentities(name); err == nil {
			fields = append(fields, "ids="+formatIdentities(ids))
		} else {
			fields = append(fields, "ids=<none>")
		}
		for _, source := range []string{"size", "ro"} {
			if data, err := os.ReadFile(filepath.Join(sysBlockDir, name, source)); err == nil {
				fields = append(fields, source+"="+quoteShort(strings.TrimSpace(string(data))))
			}
		}
		if _, err := os.Stat(filepath.Join(devDir, name)); err == nil {
			fields = append(fields, "node=ready")
		} else {
			fields = append(fields, "node=missing")
		}
		summaries = append(summaries, fmt.Sprintf("%s{%s}", name, strings.Join(fields, ",")))
	}
	if len(summaries) == 0 {
		return "none"
	}
	sort.Strings(summaries)
	return strings.Join(summaries, "; ")
}

func formatIdentities(ids []scsiIdentity) string {
	var parts []string
	for _, id := range ids {
		parts = append(parts, id.source+"="+quoteShort(id.value))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func quoteShort(value string) string {
	if len(value) > maxQuotedIdentity {
		value = value[:maxQuotedIdentity] + "..."
	}
	return strconv.Quote(value)
}

func readUevent(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			out[key] = value
		}
	}
	return out, nil
}

func filesystemUUID(dev string) (string, error) {
	f, err := os.Open(dev)
	if err != nil {
		return "", fmt.Errorf("opening filesystem probe target %s: %w", dev, err)
	}
	defer f.Close()

	buf := make([]byte, filesystemProbeBytes)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading filesystem probe target %s: %w", dev, err)
	}
	buf = buf[:n]

	if uuid, ok := erofsFilesystemUUID(buf); ok {
		return uuid, nil
	}
	if uuid, ok := extFilesystemUUID(buf); ok {
		return uuid, nil
	}
	return "", fmt.Errorf("unsupported or missing filesystem UUID in %s", dev)
}

func erofsFilesystemUUID(buf []byte) (string, bool) {
	if len(buf) < erofsUUIDOffset+uuidBytes {
		return "", false
	}
	if binary.LittleEndian.Uint32(buf[erofsMagicOffset:]) != erofsMagic {
		return "", false
	}
	return formatFilesystemUUID(buf[erofsUUIDOffset : erofsUUIDOffset+uuidBytes])
}

func extFilesystemUUID(buf []byte) (string, bool) {
	if len(buf) < extUUIDOffset+uuidBytes {
		return "", false
	}
	if binary.LittleEndian.Uint16(buf[extMagicOffset:]) != extMagic {
		return "", false
	}
	return formatFilesystemUUID(buf[extUUIDOffset : extUUIDOffset+uuidBytes])
}

func formatFilesystemUUID(raw []byte) (string, bool) {
	if len(raw) != uuidBytes {
		return "", false
	}
	nonzero := false
	for _, b := range raw {
		if b != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		return "", false
	}
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		raw[0], raw[1], raw[2], raw[3],
		raw[4], raw[5],
		raw[6], raw[7],
		raw[8], raw[9],
		raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	), true
}

func blockDeviceNodes() []string {
	var nodes []string
	for _, pattern := range []string{"*", "*/*"} {
		matches, _ := filepath.Glob(filepath.Join(sysBlockDir, pattern, "uevent"))
		for _, match := range matches {
			uevent, err := readUevent(match)
			if err != nil || uevent["DEVNAME"] == "" {
				continue
			}
			nodes = appendDeviceIfReady(nodes, uevent["DEVNAME"])
		}
	}
	sort.Strings(nodes)
	return nodes
}

func globDev(pattern string) []string {
	matches, _ := filepath.Glob(filepath.Join(devDir, pattern))
	sort.Strings(matches)
	return matches
}

func chgrpMode(path string, gid int, mode os.FileMode) error {
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func groupID(name string) (int, error) {
	data, err := os.ReadFile(groupFile)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", groupFile, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, name+":") {
			fields := strings.Split(line, ":")
			if len(fields) < 3 {
				break
			}
			gid, err := strconv.Atoi(fields[2])
			if err != nil {
				return 0, fmt.Errorf("parsing gid for %s: %w", name, err)
			}
			return gid, nil
		}
	}
	return 0, fmt.Errorf("group %s not found", name)
}
