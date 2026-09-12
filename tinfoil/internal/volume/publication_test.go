package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	config "github.com/tinfoilsh/tinfoil-config"
)

func TestPublicationFailuresNeverPublishReadiness(t *testing.T) {
	for _, stage := range []string{"layout", "seal", "export"} {
		t.Run(stage, func(t *testing.T) {
			d := disk("workspace", config.VolumeUnlock{Runtime: "owner"})
			k := &fakeMountKernel{}
			tree := testTree(t, k, true)
			d.Target = tree.root
			k.events = nil
			d.Exports = []string{t.TempDir(), t.TempDir()}
			if stage == "export" {
				k.failMount = d.Exports[1]
			}
			if stage == "layout" {
				d.Links = []Link{{Path: "profile", Target: "/expected/profile"}}
				if err := os.WriteFile(filepath.Join(d.Target, "profile"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			r := &mountedVolume{definition: d, tree: tree, seal: func([]byte) error {
				k.events = append(k.events, "seal")
				if stage == "seal" {
					return errors.New("seal failed")
				}
				return nil
			}, undo: []func() error{
				func() error { k.events = append(k.events, "close:device"); return nil }, tree.Close,
			}}
			b := &fakeBackend{prepare: func(context.Context, Definition, []byte, map[string]string) (resource, error) {
				return r, prepareLayout(d)
			}}
			m := testManager(t, Plan{Volumes: []Definition{d}}, nil, b)
			if err := m.Activate(t.Context(), d.Name, make([]byte, 64), []byte("owner")); err == nil {
				t.Fatal("expected failure")
			}
			status := m.Snapshot().Volumes[0]
			want := "failed"
			if stage == "layout" {
				want = "locked"
			}
			if status.Phase != want || status.Path != "" {
				t.Fatalf("status = %+v", status)
			}
			if stage == "layout" && slices.Contains(k.events, "seal") {
				t.Fatal("sealed before layout completed")
			}
			if stage != "layout" {
				before := slices.Clone(k.events)
				if err := m.Activate(t.Context(), d.Name, make([]byte, 64), []byte("another owner")); err == nil {
					t.Fatal("retried an owner seal")
				}
				if !slices.Equal(before, k.events) {
					t.Fatal("retry touched resources")
				}
				if !r.Committed() {
					t.Fatal("cleanup erased seal-attempt state")
				}
			}
			if stage == "export" && !slices.Equal(k.events, []string{"seal", "mount:" + d.Exports[0], "mount:" + d.Exports[1], "unmount:" + d.Exports[0], "unmount:" + d.Target, "close:device"}) {
				t.Fatal(k.events)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
