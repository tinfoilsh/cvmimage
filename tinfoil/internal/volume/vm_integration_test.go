package volume

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"tinfoil/internal/devicemapper"
	"tinfoil/internal/runtimeconfig"
)

const vmStageEnv = "TINFOIL_VOLUME_VM_STAGE"

func TestVolumeVM(t *testing.T) {
	stage := os.Getenv(vmStageEnv)
	if stage == "" {
		t.Skip("only run by the owned-scratch-disk QEMU fixture in tests/volume-vm")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(" "+strings.TrimSpace(string(cmdline))+" ", " tinfoil-volume-fixture=1 ") {
		t.Fatal("refusing block access outside the volume fixture VM")
	}
	if stage != "initialize" && stage != "reopen" {
		t.Fatalf("invalid fixture stage %q", stage)
	}
	spec := Spec{VolumeSpec: runtimeconfig.VolumeSpec{Name: "fixture"}}
	w, err := openVolume(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.closeDevices()
	if mounted, err := w.prepare(); err != nil || mounted {
		t.Fatalf("fresh boot prepare = %t, %v", mounted, err)
	}
	app := startVolumeApp(t, w.dataPath(), filepath.Join(t.TempDir(), "app"))
	app.check("locked before key", true)
	key := bytes.Repeat([]byte{0x5a}, KeyBytes)
	wrong := bytes.Repeat([]byte{0xa5}, KeyBytes)
	handle := func(op string, key []byte, want string) {
		t.Helper()
		packet, err := json.Marshal(request{Op: op, Key: key})
		if err != nil {
			t.Fatal(err)
		}
		status, err := w.handle(t.Context(), packet)
		if status != want || (want == statusOK || want == statusLocked) && err != nil {
			t.Fatalf("%s returned %q, %v; want %q", op, status, err, want)
		}
		t.Logf("%s: status=%s", op, status)
	}
	handle(opStatus, nil, statusLocked)
	before := hashFixtureDisk(t, w.source)
	handle(opUnlock, nil, statusRejected)
	if stage == "initialize" {
		handle(opUnlock, key, statusFailed)
		assertFixtureHash(t, w.source, before)
		app.check("failed unlock of blank disk", true)
		handle(opInitialize, key, statusOK)
		if !w.unlocked {
			t.Fatal("successful initialize did not set worker exit condition")
		}
	} else {
		handle(opInitialize, wrong, statusRejected)
		handle(opUnlock, wrong, statusFailed)
		if err := Mount(t.Context(), spec, wrong); err == nil {
			t.Fatal("boot Mount accepted wrong key")
		}
		assertFixtureHash(t, w.source, before)
		app.check("wrong key and refused reinitialize", true)
		if err := Mount(t.Context(), spec, key); err != nil {
			t.Fatalf("same-key Mount after VM restart: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(w.dataPath(), "payload"))
		if err != nil || string(data) != appPayload {
			t.Fatalf("persisted payload = %q, %v", data, err)
		}
		t.Logf("same-key Mount after VM restart recovered payload SHA256=%x", sha256.Sum256(data))
	}
	beforeMount, err := readMountState(w.dataPath())
	if err != nil {
		t.Fatal(err)
	}
	if mounted, err := w.prepare(); err != nil || !mounted {
		t.Fatalf("unlocked prepare = %t, %v", mounted, err)
	}
	afterMount, err := readMountState(w.dataPath())
	if err != nil || beforeMount != afterMount {
		t.Fatalf("unlocked prepare changed mount: %v, %v, %v", beforeMount, afterMount, err)
	}
	app.check("encrypted filesystem live in same app", false)
	if err := unix.Unmount(w.dataPath(), 0); err != nil {
		t.Fatal(err)
	}
	app.check("unmounted encrypted filesystem", true)
	for _, name := range []string{w.mapperName(), w.integrityName()} {
		if err := devicemapper.Remove(w.control, name); err != nil {
			t.Fatal(err)
		}
	}
	unix.Sync()
}

func hashFixtureDisk(t *testing.T, disk *os.File) [sha256.Size]byte {
	t.Helper()
	if err := unix.IoctlSetInt(int(disk.Fd()), unix.BLKFLSBUF, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := disk.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, disk); err != nil {
		t.Fatal(err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func assertFixtureHash(t *testing.T, disk *os.File, before [sha256.Size]byte) {
	t.Helper()
	after := hashFixtureDisk(t, disk)
	t.Logf("rejected operations disk SHA256: before=%x after=%x", before, after)
	if before != after {
		t.Fatal("rejected key/initialize operation changed the scratch disk")
	}
}
