package volume

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"tinfoil/internal/secretstore"
)

type Status struct {
	Name   string `json:"name"`
	Phase  string `json:"phase"`
	Path   string `json:"path,omitempty"`
	Access string `json:"access"`
	Error  string `json:"error,omitempty"`
}
type Snapshot struct {
	Initialized bool     `json:"initialized"`
	Nonce       string   `json:"nonce"`
	Volumes     []Status `json:"volumes"`
}

// resource retains activation state and anything still owned after a failure.
type resource interface {
	Publish([]byte) error
	Close() error
	Committed() bool
}

type entry struct {
	definition Definition
	status     Status
	key        []byte
	resource   resource
}
type Manager struct {
	mu          sync.Mutex
	operations  sync.WaitGroup
	prepare     func(context.Context, Definition, []byte, map[string]string) (resource, error)
	entries     map[string]*entry
	order       []string
	active      []string
	nonce       string
	closing     bool
	initialized bool
}

func NewManager(p Plan, keys secretstore.Store) (*Manager, error) {
	m := &Manager{prepare: prepareVolume, entries: map[string]*entry{}, nonce: rand.Text()}
	for _, d := range p.Volumes {
		if _, exists := m.entries[d.Name]; exists {
			m.eraseKeys()
			return nil, fmt.Errorf("duplicate volume %q", d.Name)
		}
		e := &entry{definition: d, status: Status{Name: d.Name, Phase: "locked", Access: d.Access}}
		if name := d.Unlock.Secret; name != "" {
			key, err := DecodeKey(keys.GetSecret(name))
			if err != nil {
				m.eraseKeys()
				return nil, fmt.Errorf("volume %q: %w", d.Name, err)
			}
			e.key = key
		}
		if d.Disk != nil {
			e.status.Phase = "waiting-device"
		}
		m.entries[d.Name] = e
		m.order = append(m.order, d.Name)
	}
	return m, nil
}
func DecodeKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil || len(key) != 64 {
		clear(key)
		return nil, errors.New("volume key must be base64 for 64 bytes")
	}
	return key, nil
}
func (m *Manager) eraseKeys() {
	for _, e := range m.entries {
		clear(e.key)
		e.key = nil
	}
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := Snapshot{Nonce: m.nonce, Initialized: m.initialized}
	for _, name := range m.order {
		result.Volumes = append(result.Volumes, m.entries[name].status)
	}
	return result
}
func (m *Manager) Definition(name string) (Definition, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[name]
	if !ok {
		return Definition{}, false
	}
	return e.definition, true
}

// readyLowers resolves overlay references from published mounts while m.mu is held.
func (m *Manager) readyLowers(d Definition) (map[string]string, error) {
	paths := make(map[string]string, len(d.Overlays))
	for _, overlay := range d.Overlays {
		lower, ok := m.entries[overlay.Volume]
		if !ok || lower.status.Phase != "ready" {
			return nil, fmt.Errorf("volume %s is waiting for %s", d.Name, overlay.Volume)
		}
		paths[overlay.Volume] = lower.status.Path
	}
	return paths, nil
}

// Initialize opens available boot volumes before publishing service readiness.
// Volumes waiting for runtime keys or lower packs remain pending.
func (m *Manager) Initialize(ctx context.Context, attached []string) error {
	if err := m.OpenInitial(ctx, attached); err != nil {
		return err
	}
	m.mu.Lock()
	m.initialized = true
	m.mu.Unlock()
	return nil
}

// OpenInitial mounts packs and explicitly attached secret-backed disks. A
// placeholder device is never treated as permission to initialize storage.
func (m *Manager) OpenInitial(ctx context.Context, attached []string) error {
	for _, name := range m.order {
		m.mu.Lock()
		e := m.entries[name]
		d := e.definition
		available := (e.status.Phase == "waiting-device" || e.status.Phase == "locked") && !m.closing
		if _, err := m.readyLowers(d); err != nil {
			available = false
		}
		m.mu.Unlock()
		if !available {
			continue
		}
		if d.Unlock.Runtime != "" {
			continue
		}
		if d.Disk != nil && !slices.Contains(attached, name) {
			continue
		}
		if err := m.Activate(ctx, name, nil, nil); err != nil {
			// A signed request may have started the same activation meanwhile.
			m.mu.Lock()
			phase := m.entries[name].status.Phase
			m.mu.Unlock()
			if phase != "ready" && phase != "opening" {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) Activate(ctx context.Context, name string, key, binding []byte) error {
	m.mu.Lock()
	e, ok := m.entries[name]
	if !ok || m.closing {
		m.mu.Unlock()
		return errors.New("volume unavailable")
	}
	if e.status.Phase == "ready" || e.status.Phase == "opening" || e.status.Phase == "failed" {
		phase := e.status.Phase
		m.mu.Unlock()
		return fmt.Errorf("volume %s is %s", name, phase)
	}
	d := e.definition
	if d.Unlock.Runtime == "owner" && len(binding) == 0 {
		m.mu.Unlock()
		return errors.New("owner binding required")
	}
	lowerPaths, err := m.readyLowers(d)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	material := slices.Clone(key)
	if d.Unlock.Secret != "" {
		if len(key) != 0 {
			m.mu.Unlock()
			clear(material)
			return errors.New("runtime key cannot replace a declared secret")
		}
		material = slices.Clone(e.key)
	}
	if d.Unlock.Secret != "" || d.Unlock.Runtime != "" {
		if len(material) != 64 {
			m.mu.Unlock()
			clear(material)
			return errors.New("volume requires a 64-byte key")
		}
	}
	e.status.Phase = "opening"
	e.status.Error = ""
	m.operations.Add(1)
	m.mu.Unlock()
	defer m.operations.Done()
	defer clear(material)
	resource, err := m.prepare(ctx, d, material, lowerPaths)
	if err == nil {
		err = resource.Publish(binding)
	}
	committed := resource != nil && resource.Committed()
	if err != nil && resource != nil {
		if closeErr := resource.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			committed = true
			m.mu.Lock()
			e.resource = resource
			m.active = append(m.active, name)
			m.mu.Unlock()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		e.status.Phase = "locked"
		if committed {
			e.status.Phase = "failed"
		}
		e.status.Error = "activation failed"
		return err
	}
	clear(e.key)
	e.key = nil
	e.resource = resource
	e.status.Phase = "ready"
	e.status.Path = d.Target
	m.active = append(m.active, name)
	return nil
}
func (m *Manager) Close() error {
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	m.operations.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.eraseKeys()
	for len(m.active) > 0 {
		i := len(m.active) - 1
		e := m.entries[m.active[i]]
		if err := e.resource.Close(); err != nil {
			return err
		}
		e.status.Phase = "closed"
		e.status.Path = ""
		e.resource = nil
		m.active = m.active[:i]
	}
	return nil
}
