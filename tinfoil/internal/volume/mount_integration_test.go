package volume

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const mountTestEnv = "TINFOIL_VOLUME_MOUNT_TEST"

func TestLockedMountPropagation(t *testing.T) {
	if os.Getenv(mountTestEnv) == "" {
		t.Skip("requires explicit TINFOIL_VOLUME_MOUNT_TEST=1 and CAP_SYS_ADMIN; no block devices used")
	}
	if os.Getenv(mountTestEnv) != "child" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLockedMountPropagation$", "-test.v")
		cmd.Env = []string{mountTestEnv + "=child"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated mount test: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		flags uintptr
	}{
		{"relatime", unix.MS_RELATIME},
		{"relatime-nodiratime", unix.MS_RELATIME | unix.MS_NODIRATIME},
		{"noatime", unix.MS_NOATIME},
		{"noatime-nodiratime", unix.MS_NOATIME | unix.MS_NODIRATIME},
		{"strictatime", unix.MS_STRICTATIME},
		{"strictatime-nodiratime", unix.MS_STRICTATIME | unix.MS_NODIRATIME},
	} {
		t.Run(test.name, func(t *testing.T) {
			testLockedMountPropagation(t, test.flags)
		})
	}
}

func testLockedMountPropagation(t *testing.T, atimeFlags uintptr) {
	root := t.TempDir()
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NOSYMFOLLOW|atimeFlags, "size=16m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(root, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "target"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(source, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	checkSymlink := func() {
		t.Helper()
		if _, err := os.ReadFile(link); !errors.Is(err, unix.ELOOP) {
			t.Fatalf("symlink traversal = %v, want ELOOP", err)
		}
	}
	checkSymlink()
	var inherited unix.Statfs_t
	if err := unix.Statfs(source, &inherited); err != nil {
		t.Fatal(err)
	}
	inspect := func() (bool, error) {
		target, parent, err := mountStates(source)
		return target.device != parent.device, err
	}
	prepare := func(wantMounted bool) {
		t.Helper()
		mounted, err := prepareDataMount(source, inspect, unix.Mount)
		if err != nil || mounted != wantMounted {
			t.Fatalf("prepare = %t, %v; want mounted %t", mounted, err, wantMounted)
		}
		if !wantMounted {
			var actual unix.Statfs_t
			if err := unix.Statfs(source, &actual); err != nil {
				t.Fatal(err)
			}
			if want := inherited.Flags | unix.ST_RDONLY; actual.Flags != want {
				t.Errorf("placeholder flags = %#x, want inherited flags plus readonly %#x", actual.Flags, want)
			}
		}
	}
	prepare(false)
	checkSymlink()
	before, err := readMountState(source)
	if err != nil {
		t.Fatal(err)
	}
	prepare(false)
	after, err := readMountState(source)
	if err != nil || before != after {
		t.Fatalf("repeat prepare changed placeholder: %v, %v, %v", before, after, err)
	}
	checkSymlink()
	var info unix.Statfs_t
	if err := unix.Statfs(source, &info); err != nil {
		t.Fatal(err)
	}
	const required = unix.ST_RDONLY | unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC
	if info.Flags&required != required {
		t.Fatalf("placeholder flags = %#x, want %#x", info.Flags, required)
	}
	app := startVolumeApp(t, source, filepath.Join(root, "app"))
	app.check("locked", true)
	if err := os.WriteFile(filepath.Join(source, "denied"), nil, 0o600); !errors.Is(err, unix.EROFS) {
		t.Fatalf("source write = %v, want EROFS", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sibling"), nil, 0o600); err != nil {
		t.Fatalf("guard affected parent filesystem: %v", err)
	}
	if err := unix.Mount("tmpfs", source, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "size=4m"); err != nil {
		t.Fatal(err)
	}
	prepare(true)
	app.check("unlocked", false)
	if data, err := os.ReadFile(filepath.Join(source, "payload")); err != nil || string(data) != appPayload {
		t.Fatalf("propagated write = %q, %v", data, err)
	}
	if err := unix.Unmount(source, 0); err != nil {
		t.Fatal(err)
	}
	app.check("rolled back", true)
	checkSymlink()
}
