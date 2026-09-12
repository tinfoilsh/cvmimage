package volume

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"sync"
	"testing"

	config "github.com/tinfoilsh/tinfoil-config"
	"tinfoil/internal/modelpack"
	"tinfoil/internal/secretstore"
)

type fakeBackend struct {
	mu      sync.Mutex
	events  []string
	prepare func(context.Context, Definition, []byte, map[string]string) (resource, error)
}

func (b *fakeBackend) record(event string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
}
func (b *fakeBackend) Prepare(ctx context.Context, d Definition, key []byte, lowerPaths map[string]string) (resource, error) {
	b.record("open:" + d.Name)
	if b.prepare != nil {
		return b.prepare(ctx, d, key, lowerPaths)
	}
	return &fakeResource{backend: b, name: d.Name}, nil
}

type fakeResource struct {
	backend              *fakeBackend
	name                 string
	committed            bool
	publishErr, closeErr error
}

func (r *fakeResource) Publish([]byte) error {
	r.backend.record("publish:" + r.name)
	return r.publishErr
}
func (r *fakeResource) Close() error    { r.backend.record("close:" + r.name); return r.closeErr }
func (r *fakeResource) Committed() bool { return r.committed }
func disk(name string, u config.VolumeUnlock) Definition {
	return Definition{Name: name, Target: "/volumes/" + name, Access: "rw", Unlock: u, Filesystem: "ext4", Disk: &DiskSource{Initialize: "never"}}
}
func testManager(t *testing.T, p Plan, keys secretstore.Store, b *fakeBackend) *Manager {
	t.Helper()
	m, e := NewManager(p, keys)
	if e != nil {
		t.Fatal(e)
	}
	m.prepare = b.Prepare
	return m
}

func TestSecretKeyPreservesPackWhitespaceHandling(t *testing.T) {
	want := bytes.Repeat([]byte{7}, 64)
	got, err := DecodeKey(" \n" + base64.StdEncoding.EncodeToString(want) + "\n ")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("key decode: %v", err)
	}
}

func TestInitialSecretsAndRuntimeDependencies(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 64)
	p := Plan{Volumes: []Definition{
		{Name: "toolchain", Target: "/packs/toolchain", Pack: &modelpack.Source{}},
		disk("attached", config.VolumeUnlock{Secret: "DISK_KEY"}),
		disk("later", config.VolumeUnlock{Secret: "DISK_KEY"}),
		disk("workspace", config.VolumeUnlock{Runtime: "owner"}),
	}}
	p.Volumes[3].Overlays = []Overlay{{Volume: "toolchain", Source: "nix/store", Target: "store"}}
	b := &fakeBackend{}
	m := testManager(t, p, secretstore.Store{"DISK_KEY": base64.StdEncoding.EncodeToString(key)}, b)
	if m.Snapshot().Initialized {
		t.Fatal("published readiness before initialization")
	}
	if err := m.Activate(t.Context(), "workspace", key, []byte("owner")); err == nil {
		t.Fatal("opened before lower was ready")
	}
	if err := m.Initialize(t.Context(), []string{"attached"}); err != nil {
		t.Fatal(err)
	}
	state := m.Snapshot()
	if !state.Initialized {
		t.Fatal("pending runtime volumes prevented service readiness")
	}
	if state.Volumes[0].Phase != "ready" || state.Volumes[1].Phase != "ready" || state.Volumes[2].Phase != "waiting-device" || state.Volumes[3].Path != "" {
		t.Fatalf("state: %+v", state)
	}
	if m.entries["attached"].key != nil || len(m.entries["later"].key) != 64 {
		t.Fatal("incorrect key retention")
	}
	if err := m.Activate(t.Context(), "later", key, nil); err == nil {
		t.Fatal("replaced a measured secret")
	}
	if err := m.Activate(t.Context(), "workspace", key, nil); err == nil {
		t.Fatal("accepted missing owner binding")
	}
	if err := m.Activate(t.Context(), "workspace", key, []byte("owner")); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(t.Context(), "later", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	var closed []string
	for _, e := range b.events {
		if len(e) > 6 && e[:6] == "close:" {
			closed = append(closed, e)
		}
	}
	if !slices.Equal(closed, []string{"close:later", "close:workspace", "close:attached", "close:toolchain"}) {
		t.Fatalf("close order: %v", closed)
	}
}
func TestActivationFailureAndRetry(t *testing.T) {
	for _, tt := range []struct {
		name                      string
		committed, cleanupFailure bool
		want                      string
	}{
		{"wrong key", false, false, "locked"}, {"owner seal", true, false, "failed"}, {"busy cleanup", false, true, "failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := &fakeBackend{}
			r := &fakeResource{backend: b, name: "state", committed: tt.committed, publishErr: errors.New("activation failure")}
			if tt.cleanupFailure {
				r.closeErr = errors.New("busy")
			}
			var supplied []byte
			b.prepare = func(_ context.Context, _ Definition, key []byte, _ map[string]string) (resource, error) {
				supplied = key
				return r, nil
			}
			m := testManager(t, Plan{Volumes: []Definition{disk("state", config.VolumeUnlock{Runtime: "operator"})}}, nil, b)
			key := bytes.Repeat([]byte{1}, 64)
			if err := m.Activate(t.Context(), "state", key, nil); err == nil {
				t.Fatal("expected failure")
			}
			if !bytes.Equal(supplied, make([]byte, 64)) || key[0] != 1 {
				t.Fatal("activation key copy not erased correctly")
			}
			if got := m.Snapshot().Volumes[0]; got.Phase != tt.want || got.Path != "" {
				t.Fatalf("status %+v", got)
			}
			r.publishErr = nil
			err := m.Activate(t.Context(), "state", key, nil)
			if (err == nil) != (tt.want == "locked") {
				t.Fatalf("retry: %v", err)
			}
			r.closeErr = nil
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPartialPreparationIsClosed(t *testing.T) {
	b := &fakeBackend{}
	r := &fakeResource{backend: b, name: "state"}
	b.prepare = func(context.Context, Definition, []byte, map[string]string) (resource, error) {
		return r, errors.New("overlay failed")
	}
	m := testManager(t, Plan{Volumes: []Definition{disk("state", config.VolumeUnlock{Runtime: "operator"})}}, nil, b)
	if err := m.Activate(t.Context(), "state", make([]byte, 64), nil); err == nil {
		t.Fatal("expected error")
	}
	if !slices.Equal(b.events, []string{"open:state", "close:state"}) {
		t.Fatal(b.events)
	}
}
func TestConcurrentActivationAndShutdown(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	b := &fakeBackend{}
	b.prepare = func(ctx context.Context, d Definition, key []byte, _ map[string]string) (resource, error) {
		close(entered)
		<-release
		return &fakeResource{backend: b, name: d.Name}, nil
	}
	m := testManager(t, Plan{Volumes: []Definition{disk("state", config.VolumeUnlock{Runtime: "operator"})}}, nil, b)
	done := make(chan error, 1)
	go func() { done <- m.Activate(t.Context(), "state", make([]byte, 64), nil) }()
	<-entered
	if m.Snapshot().Volumes[0].Phase != "opening" {
		t.Fatal("missing opening state")
	}
	if err := m.Activate(t.Context(), "state", make([]byte, 64), nil); err == nil {
		t.Fatal("concurrent activation accepted")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- m.Close() }()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().Volumes[0].Phase != "closed" {
		t.Fatal("shutdown lost an in-flight mount")
	}
	if err := m.Activate(t.Context(), "state", make([]byte, 64), nil); err == nil {
		t.Fatal("activation after close")
	}
}
func TestCleanupStopsAtBusyMountAndCanResume(t *testing.T) {
	var events []string
	busy := true
	r := &mountedVolume{undo: []func() error{
		func() error { events = append(events, "mapping"); return nil },
		func() error { events = append(events, "base"); return nil },
		func() error {
			events = append(events, "overlay")
			if busy {
				return errors.New("busy")
			}
			return nil
		},
		func() error { events = append(events, "export"); return nil },
	}}
	if err := r.Close(); err == nil {
		t.Fatal("expected busy")
	}
	if !slices.Equal(events, []string{"export", "overlay"}) {
		t.Fatal(events)
	}
	busy = false
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"export", "overlay", "overlay", "base", "mapping"}) {
		t.Fatal(events)
	}
}

func TestSecretUpperWaitsForRuntimeLower(t *testing.T) {
	upper := disk("state", config.VolumeUnlock{Secret: "KEY"})
	upper.Overlays = []Overlay{{Volume: "lower", Source: "nix/store", Target: "store"}}
	lower := Definition{Name: "lower", Target: "/packs/lower", Access: "ro", Unlock: config.VolumeUnlock{Runtime: "operator"}, Pack: &modelpack.Source{Encrypted: true}}
	b := &fakeBackend{}
	m := testManager(t, Plan{Volumes: []Definition{lower, upper}}, secretstore.Store{"KEY": base64.StdEncoding.EncodeToString(make([]byte, 64))}, b)
	if err := m.OpenInitial(t.Context(), []string{"state"}); err != nil {
		t.Fatal(err)
	}
	if len(b.events) != 0 {
		t.Fatal("mounted upper before its lower")
	}
	if err := m.Activate(t.Context(), "lower", make([]byte, 64), nil); err != nil {
		t.Fatal(err)
	}
	if err := m.OpenInitial(t.Context(), []string{"state"}); err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().Volumes[1].Phase != "ready" {
		t.Fatal("secret upper did not activate")
	}
	if err := m.OpenInitial(t.Context(), []string{"state"}); err != nil {
		t.Fatal("repeated automatic activation was not idempotent")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerCloseForgetsCompletedResources(t *testing.T) {
	b := &fakeBackend{}
	resources := map[string]*fakeResource{}
	b.prepare = func(_ context.Context, d Definition, _ []byte, _ map[string]string) (resource, error) {
		r := &fakeResource{backend: b, name: d.Name}
		resources[d.Name] = r
		return r, nil
	}
	m := testManager(t, Plan{Volumes: []Definition{
		disk("first", config.VolumeUnlock{Runtime: "operator"}),
		disk("second", config.VolumeUnlock{Runtime: "operator"}),
	}}, nil, b)
	for _, name := range []string{"first", "second"} {
		if err := m.Activate(t.Context(), name, make([]byte, 64), nil); err != nil {
			t.Fatal(err)
		}
	}
	resources["first"].closeErr = errors.New("busy")
	b.events = nil
	if err := m.Close(); err == nil {
		t.Fatal("expected busy first volume")
	}
	status := m.Snapshot().Volumes[1]
	if status.Phase != "closed" || status.Path != "" || m.entries["second"].resource != nil {
		t.Fatal("completed resource was retained")
	}
	resources["first"].closeErr = nil
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.events, []string{"close:second", "close:first", "close:first"}) {
		t.Fatal(b.events)
	}
}
