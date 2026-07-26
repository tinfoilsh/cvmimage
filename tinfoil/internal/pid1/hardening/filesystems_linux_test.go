package hardening

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

type mountCall struct {
	source         string
	target         string
	filesystemType string
	flags          uintptr
	data           string
}

type fakeFilesystemKernel struct {
	failAt int
	err    error
	calls  []mountCall
}

func (kernel *fakeFilesystemKernel) unshare(flags int) error {
	kernel.calls = append(kernel.calls, mountCall{source: "unshare", flags: uintptr(flags)})
	if kernel.failAt == len(kernel.calls) {
		return kernel.err
	}
	return nil
}

func (kernel *fakeFilesystemKernel) mount(source, target, filesystemType string, flags uintptr, data string) error {
	kernel.calls = append(kernel.calls, mountCall{
		source:         source,
		target:         target,
		filesystemType: filesystemType,
		flags:          flags,
		data:           data,
	})
	if kernel.failAt == len(kernel.calls) {
		return kernel.err
	}
	return nil
}

func TestRestrictServiceFilesystemsUsesFixedPrivateReadOnlyLayout(t *testing.T) {
	kernel := &fakeFilesystemKernel{}
	if err := restrictServiceFilesystems(kernel); err != nil {
		t.Fatalf("restrictServiceFilesystems: %v", err)
	}

	baseFlags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	want := []mountCall{
		{source: "unshare", flags: unix.CLONE_NEWNS},
		{target: "/", flags: unix.MS_REC | unix.MS_PRIVATE},
		{source: "proc", target: "/proc", filesystemType: "proc", flags: baseFlags, data: "hidepid=2"},
		{target: "/proc", flags: baseFlags | unix.MS_REMOUNT | unix.MS_RDONLY},
		{source: "tmpfs", target: "/dev", filesystemType: "tmpfs", flags: baseFlags, data: "size=4k,nr_inodes=1,mode=0555"},
		{target: "/dev", flags: baseFlags | unix.MS_REMOUNT | unix.MS_RDONLY},
		{source: "tmpfs", target: "/sys", filesystemType: "tmpfs", flags: baseFlags, data: "size=4k,nr_inodes=1,mode=0555"},
		{target: "/sys", flags: baseFlags | unix.MS_REMOUNT | unix.MS_RDONLY},
	}
	if !reflect.DeepEqual(kernel.calls, want) {
		t.Fatalf("filesystem calls =\n%#v\nwant\n%#v", kernel.calls, want)
	}
}

func TestRestrictServiceFilesystemsFailsClosedAtEveryStep(t *testing.T) {
	for failAt := 1; failAt <= 8; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			stepErr := errors.New("step failed")
			kernel := &fakeFilesystemKernel{failAt: failAt, err: stepErr}
			err := restrictServiceFilesystems(kernel)
			if !errors.Is(err, stepErr) {
				t.Fatalf("error = %v, want %v", err, stepErr)
			}
			if len(kernel.calls) != failAt {
				t.Fatalf("calls = %d, want %d", len(kernel.calls), failAt)
			}
		})
	}
}
