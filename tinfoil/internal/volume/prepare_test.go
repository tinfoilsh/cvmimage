package volume

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareDataMount(t *testing.T) {
	failure := errors.New("injected failure")
	for _, test := range []struct {
		name        string
		mounted     bool
		inspectErr  error
		remountErr  error
		wantRemount bool
	}{
		{name: "locked", wantRemount: true},
		{name: "unlocked", mounted: true},
		{name: "inspection fails", inspectErr: failure},
		{name: "protection fails", remountErr: failure, wantRemount: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			remounted := false
			mounted, err := prepareDataMount(t.TempDir(), func() (bool, error) {
				return test.mounted, test.inspectErr
			}, func(_, _, _ string, flags uintptr, _ string) error {
				if flags&unix.MS_REMOUNT != 0 {
					remounted = true
					if flags&unix.MS_RDONLY == 0 {
						t.Fatal("placeholder remount is not read-only")
					}
					return test.remountErr
				}
				return nil
			})
			wantErr := errors.Join(test.inspectErr, test.remountErr)
			if (wantErr != nil && !errors.Is(err, failure)) || (wantErr == nil && err != nil) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			if mounted != test.mounted || remounted != test.wantRemount {
				t.Fatalf("mounted=%t remounted=%t; want %t, %t", mounted, remounted, test.mounted, test.wantRemount)
			}
		})
	}
}
