package modelpack

import (
	"fmt"
	"strconv"

	"github.com/tinfoilsh/modelwrap"
	"tinfoil/internal/devicemapper"
)

// Device owns the mappings acquired while opening a pack.
type Device struct {
	verity mapping
	undo   []func() error
}

func (m *Device) Path() string         { return m.verity.Path() }
func (m *Device) DeviceNumber() uint64 { return m.verity.DeviceNumber() }

func (m *Device) Close() error {
	if m == nil {
		return nil
	}
	for len(m.undo) > 0 {
		i := len(m.undo) - 1
		if err := m.undo[i](); err != nil {
			return err
		}
		m.undo = m.undo[:i]
	}
	return nil
}

// Open borrows masterKey and returns a verified block device. Path and
// DeviceNumber are valid on success. Close must also be called on a partial
// handle returned with an error; it retains mappings whose cleanup can fail.
func Open(source Source, sourceDevice string, masterKey []byte) (*Device, error) {
	return openPack(linuxPackOps{}, source, sourceDevice, masterKey)
}

type mapping interface {
	Path() string
	DeviceNumber() uint64
	Close() error
}
type packOps interface {
	openVerity(string, *modelwrap.ArtifactRef, []byte) (mapping, error)
	openCrypt(string, string, []byte) (mapping, error)
}

func openPack(ops packOps, source Source, sourceDevice string, masterKey []byte) (*Device, error) {
	if err := source.Validate(); err != nil {
		return nil, err
	}
	if source.Encrypted && len(masterKey) != modelwrap.EMWPMasterKeyBytes {
		return nil, fmt.Errorf("encrypted pack requires a %d-byte master key", modelwrap.EMWPMasterKeyBytes)
	}
	if !source.Encrypted && len(masterKey) != 0 {
		return nil, fmt.Errorf("plaintext pack cannot receive a key")
	}
	ref, _ := modelwrap.ParseRef(source.Ref)
	m := &Device{}
	if source.Encrypted {
		key, err := modelwrap.DeriveKey(masterKey, ref)
		if err != nil {
			return m, err
		}
		crypt, err := ops.openCrypt(sourceDevice, "emwp-"+ref.RootHash+"-crypt", key)
		clear(key)
		if crypt != nil {
			m.undo = append(m.undo, crypt.Close)
		}
		if err != nil {
			return m, err
		}
		sourceDevice = crypt.Path()
	}
	verity, err := ops.openVerity(sourceDevice, ref, modelwrap.VeritySalt(source.Repo))
	if verity != nil {
		m.undo = append(m.undo, verity.Close)
	}
	if err != nil {
		return m, err
	}
	m.verity = verity
	return m, nil
}

type linuxPackOps struct{}

func parseHashOffset(value string) (uint64, error) {
	offset, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid verity hash offset %q: %w", value, err)
	}
	return offset, nil
}

func (linuxPackOps) openVerity(source string, ref *modelwrap.ArtifactRef, salt []byte) (mapping, error) {
	offset, err := parseHashOffset(ref.HashOffset)
	if err != nil {
		return nil, err
	}
	length, params, err := fixedVerityTable(source, ref.RootHash, offset, salt)
	if err != nil {
		return nil, err
	}
	control, err := devicemapper.OpenControl()
	if err != nil {
		return nil, err
	}
	defer control.Close()
	if _, err := devicemapper.CheckVersion(control); err != nil {
		return nil, err
	}
	name := "mwp-" + ref.RootHash
	m, err := devicemapper.OpenReadOnly(control, name, func() error { return devicemapper.LoadReadOnlyVerityTable(control, name, length, params) })
	if m == nil {
		return nil, err
	}
	return m, err
}

func (linuxPackOps) openCrypt(source, name string, key []byte) (mapping, error) {
	number, length, err := devicemapper.BlockDeviceInfo(source)
	if err != nil {
		return nil, err
	}
	params, err := devicemapper.CryptTable(number, key, length)
	if err != nil {
		return nil, err
	}
	defer clear(params)
	control, err := devicemapper.OpenControl()
	if err != nil {
		return nil, err
	}
	defer control.Close()
	if _, err := devicemapper.CheckVersion(control); err != nil {
		return nil, err
	}
	m, err := devicemapper.OpenReadOnly(control, name, func() error { return devicemapper.LoadReadOnlyCryptTable(control, name, length, params) })
	if m == nil {
		return nil, err
	}
	return m, err
}
