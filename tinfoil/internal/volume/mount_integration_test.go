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
		{"relatime-nodiratime", unix.MS_RELATIME | unix.MS_NODIRATIME},
		{"noatime", unix.MS_NOATIME},
		{"strictatime-nodiratime", unix.MS_STRICTATIME | unix.MS_NODIRATIME},
	} {
		t.Run(test.name, func(t *testing.T) {
			testLockedMountPropagation(t, test.flags)
		})
	}
}

func testLockedMountPropagation(t *testing.T, atimeFlags uintptr) {
	root := t.TempDir()
	const tmpfsOptions = "size=4m"
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NOSYMFOLLOW|atimeFlags, tmpfsOptions); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(root, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	source := filepath.Join(root, "source")
	app := filepath.Join(root, "app")
	for _, path := range []string{source, app} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
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
	if err := unix.Mount(source, app, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", app, "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	checkLocked := func() {
		t.Helper()
		for _, path := range []string{source, app} {
			if err := os.WriteFile(filepath.Join(path, "payload"), nil, 0o600); !errors.Is(err, unix.EROFS) {
				t.Fatalf("write to %s = %v, want EROFS", path, err)
			}
		}
	}
	checkLocked()
	prepare(false)
	checkLocked()
	if err := os.WriteFile(filepath.Join(root, "sibling"), nil, 0o600); err != nil {
		t.Fatalf("guard affected parent filesystem: %v", err)
	}
	if err := unix.Mount("tmpfs", source, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, tmpfsOptions); err != nil {
		t.Fatal(err)
	}
	prepare(true)
	const payload = "unlocked volume"
	if err := os.WriteFile(filepath.Join(app, "payload"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write through existing bind after unlock: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(source, "payload")); err != nil || string(data) != payload {
		t.Fatalf("propagated write = %q, %v", data, err)
	}
	if err := unix.Unmount(source, 0); err != nil {
		t.Fatal(err)
	}
	checkLocked()
}
