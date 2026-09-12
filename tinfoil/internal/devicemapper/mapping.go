package devicemapper

import (
	"fmt"
	"os"
)

// Mapping owns a kernel mapping from successful creation through removal.
// Activation functions return it on partial failure as well as success.
type Mapping struct {
	name       string
	Device     uint64
	remove     func(string) error
	removeNode func(string) error
}

func (m *Mapping) Path() string         { return MapperNode(m.name) }
func (m *Mapping) DeviceNumber() uint64 { return m.Device }

// Close retains ownership on failure, so a busy mapping can be closed later.
func (m *Mapping) Close() error {
	if m == nil {
		return nil
	}
	if m.remove != nil {
		if err := m.remove(m.name); err != nil {
			return fmt.Errorf("remove mapping %s: %w", m.name, err)
		}
		m.remove = nil
	}
	if m.removeNode != nil {
		if err := m.removeNode(m.name); err != nil {
			return err
		}
		m.removeNode = nil
	}
	return nil
}

func removeMapping(name string) error {
	control, err := OpenControl()
	if err != nil {
		return err
	}
	defer control.Close()
	return removeDevice(control, name)
}

func newMapping(control *os.File, name string, readOnly bool) (*Mapping, error) {
	m, err := createMapping(name, func() error { _, err := create(control, name, mappingFlags(readOnly)); return err }, removeMapping)
	if m != nil {
		m.removeNode = removeMapperNode
	}
	return m, err
}

func createMapping(name string, create func() error, remove func(string) error) (*Mapping, error) {
	if err := create(); err != nil {
		return nil, err
	}
	return &Mapping{name: name, remove: remove}, nil
}

func finishMapping(control *os.File, m *Mapping, readOnly bool) error {
	if err := resume(control, m.name, mappingFlags(readOnly)); err != nil {
		return err
	}
	info, err := Status(control, m.name)
	if err != nil {
		return err
	}
	if !info.Active() || info.ReadOnly() != readOnly || info.TargetCount != 1 {
		return fmt.Errorf("mapping %s has unexpected state: active=%t read-only=%t targets=%d", m.name, info.Active(), info.ReadOnly(), info.TargetCount)
	}
	m.Device = info.Dev
	return EnsureBlockNode(m.Path(), info.Dev)
}

// OpenReadOnly retains any created mapping even if loading or resuming fails.
func OpenReadOnly(control *os.File, name string, load func() error) (*Mapping, error) {
	m, err := newMapping(control, name, true)
	if err != nil {
		return nil, err
	}
	if err := load(); err != nil {
		return m, err
	}
	return m, finishMapping(control, m, true)
}
