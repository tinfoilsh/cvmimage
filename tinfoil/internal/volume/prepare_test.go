package volume

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareDataMount(t *testing.T) {
	failure := errors.New("injected failure")
	for _, test := range []struct {
		name       string
		mounted    bool
		inspectErr error
		failCall   int
		wantCalls  int
	}{
		{name: "locked", wantCalls: 3},
		{name: "unlocked", mounted: true, wantCalls: 2},
		{name: "unexpected mount or mapping", inspectErr: failure, wantCalls: 2},
		{name: "bind fails", failCall: 1, wantCalls: 1},
		{name: "shared fails", failCall: 2, wantCalls: 2},
		{name: "read-only fails", failCall: 3, wantCalls: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := t.TempDir()
			var info unix.Statfs_t
			if err := unix.Statfs(path, &info); err != nil {
				t.Fatal(err)
			}
			var calls []uintptr
			inspected := false
			mounted, err := prepareDataMount(path, func() (bool, error) {
				inspected = true
				return test.mounted, test.inspectErr
			}, func(source, target, fs string, flags uintptr, data string) error {
				calls = append(calls, flags)
				if target != path || fs != "" || data != "" {
					t.Fatalf("unexpected mount arguments: %q %q %q %q", source, target, fs, data)
				}
				if len(calls) == 1 && source != path || len(calls) > 1 && source != "" {
					t.Fatalf("unexpected source %q", source)
				}
				if flags&unix.MS_RDONLY != 0 && (!inspected || test.mounted || test.inspectErr != nil) {
					t.Fatal("read-only remount before confirming a locked placeholder")
				}
				if len(calls) == test.failCall {
					return failure
				}
				return nil
			})
			wantErr := test.inspectErr != nil || test.failCall != 0
			if wantErr && !errors.Is(err, failure) || !wantErr && err != nil {
				t.Fatalf("error = %v, want failure = %t", err, wantErr)
			}
			if mounted != (test.mounted && !wantErr) {
				t.Fatalf("mounted = %t", mounted)
			}
			retained := uintptr(info.Flags) & (unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME | unix.MS_NODIRATIME | unix.MS_RELATIME)
			want := []uintptr{unix.MS_BIND, unix.MS_SHARED, unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY | retained}
			if !reflect.DeepEqual(calls, want[:test.wantCalls]) {
				t.Fatalf("mount flags = %#v, want %#v", calls, want[:test.wantCalls])
			}
		})
	}
}

func TestPrepareDataMountMissingPath(t *testing.T) {
	_, err := prepareDataMount(filepath.Join(t.TempDir(), "absent"), func() (bool, error) {
		t.Fatal("inspected missing path")
		return false, nil
	}, func(string, string, string, uintptr, string) error {
		t.Fatal("mounted missing path")
		return nil
	})
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("error = %v, want ENOENT", err)
	}
}
