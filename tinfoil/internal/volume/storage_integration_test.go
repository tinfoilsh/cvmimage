//go:build storageintegration

package volume

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	config "github.com/tinfoilsh/tinfoil-config"
	"golang.org/x/sys/unix"
	"tinfoil/internal/device"
	"tinfoil/internal/devicemapper"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--make-test-packs" {
		if err := makePackFixtures(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getpid() == 1 {
		for _, fs := range []struct{ target, kind string }{{"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev", "devtmpfs"}} {
			if err := unix.Mount(fs.kind, fs.target, fs.kind, 0, ""); err != nil {
				fmt.Fprintln(os.Stderr, err)
				_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
			}
		}
		os.Args = []string{"/init", "-test.run=^TestStorageVM$", "-test.v", "-test.timeout=90s"}
		code := m.Run()
		fmt.Printf("STORAGE_TEST_EXIT=%d\n", code)
		unix.Sync()
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// Run only in the disposable VM created by scripts/test-volumes-vm.py. No host
// block devices are passed into that VM; its writable disk is a temporary file.
func TestStorageVM(t *testing.T) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(string(cmdline), "tinfoil.storage-test=1") {
		t.Skip("requires the disposable storage test VM")
	}
	data, err := os.ReadFile("/packs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []packFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 2 {
		t.Fatal("expected plaintext and encrypted packs")
	}
	var plan Plan
	for i, fixture := range fixtures {
		selector, err := device.PackSelector(i, fixture.Source.Encrypted)
		if err != nil {
			t.Fatal(err)
		}
		name := []string{"lower", "encrypted"}[i]
		plan.Volumes = append(plan.Volumes, Definition{Name: name, Target: "/packs/" + name,
			Filesystem: "erofs", Access: "ro", Exec: true, Device: selector, Pack: &fixture.Source})
		if fixture.Source.Encrypted {
			plan.Volumes[i].Unlock.Runtime = "operator"
		}
	}
	definition := disk("state", config.VolumeUnlock{Runtime: "operator"})
	definition.Device, err = device.DiskSelector(len(fixtures), 0)
	if err != nil {
		t.Fatal(err)
	}
	definition.Disk.Initialize = "if-empty"
	definition.Exec = true
	definition.Exports = []string{"/export-one", "/export-two"}
	for _, target := range definition.Exports {
		if err := os.MkdirAll(target, 0700); err != nil {
			t.Fatal(err)
		}
	}
	definition.Overlays = []Overlay{{Volume: "lower", Source: "store", Target: "store"}}
	plan.Volumes = append(plan.Volumes, definition)
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	definition = plan.Volumes[2]
	lowerPaths := map[string]string{"lower": plan.Volumes[0].Target}
	if _, err := os.Stat("/legacy-worker"); err == nil {
		testLegacyDisk(t, len(fixtures))
	}
	key := bytes.Repeat([]byte{0x29}, 64)
	open := func(d Definition, k []byte) resource {
		t.Helper()
		r, err := prepareVolume(t.Context(), d, k, lowerPaths)
		if err != nil {
			if r != nil {
				_ = r.Close()
			}
			t.Fatal(err)
		}
		if err := r.Publish(nil); err != nil {
			_ = r.Close()
			t.Fatal(err)
		}
		return r
	}
	lower := open(plan.Volumes[0], nil)
	defer lower.Close()
	encrypted := open(plan.Volumes[1], fixturePackKey())
	contents, err := os.ReadFile(plan.Volumes[1].Target + "/store/tool")
	if err != nil || string(contents) != "toolchain\n" {
		t.Fatalf("encrypted pack: %q, %v", contents, err)
	}
	if err := os.WriteFile(plan.Volumes[1].Target+"/forbidden", nil, 0600); err == nil {
		t.Fatal("encrypted pack accepted a write")
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	wrongPack, err := prepareVolume(t.Context(), plan.Volumes[1], bytes.Repeat([]byte{0x31}, 64), nil)
	if err == nil {
		_ = wrongPack.Close()
		t.Fatal("wrong key opened encrypted pack")
	}
	if wrongPack != nil {
		if err := wrongPack.Close(); err != nil {
			t.Fatal(err)
		}
	}
	encrypted = open(plan.Volumes[1], fixturePackKey())
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("opened verified and encrypted packs; rejected a wrong pack key and reopened cleanly")
	r := open(definition, key)
	for _, root := range []string{definition.Target, "/export-one", "/export-two"} {
		data, err := os.ReadFile(filepath.Join(root, "store/tool"))
		if err != nil || string(data) != "toolchain\n" {
			t.Fatalf("lower at %s: %q, %v", root, data, err)
		}
	}
	if err := os.WriteFile("/export-two/store/new", []byte("overlay write\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/export-one/persistent", []byte("persistent state\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("recursive export cleanup: %v", err)
	}
	wrong, err := prepareVolume(t.Context(), definition, bytes.Repeat([]byte{0x31}, 64), lowerPaths)
	if err == nil {
		_ = wrong.Close()
		t.Fatal("wrong key opened disk")
	}
	if wrong != nil {
		if err := wrong.Close(); err != nil {
			t.Fatal(err)
		}
	}
	r = open(definition, key)
	data, err = os.ReadFile("/export-one/store/new")
	if err != nil || string(data) != "overlay write\n" {
		t.Fatalf("overlay did not persist: %q, %v", data, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// The same encrypted disk can be reopened with strict read-only access.
	definition.Access = "ro"
	definition.Disk.Initialize = "never"
	definition.Overlays = nil
	definition.Exports = nil
	r = open(definition, key)
	data, err = os.ReadFile(filepath.Join(definition.Target, "persistent"))
	if err != nil || string(data) != "persistent state\n" {
		t.Fatalf("read-only roundtrip: %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(definition.Target, "forbidden"), nil, 0600); err == nil {
		t.Fatal("read-only disk accepted a write")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func testLegacyDisk(t *testing.T, packCount int) {
	t.Helper()
	key := bytes.Repeat([]byte{0x15}, 64)
	command := exec.CommandContext(t.Context(), "/legacy-worker", "--name=legacy", "--index=1", fmt.Sprintf("--models=%d", packCount), "--owner=1000")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	var conn net.Conn
	var err error
	for attempt := 0; attempt < 500; attempt++ {
		conn, err = net.Dial("unixpacket", "/run/tinfoil/volumes/legacy/control.sock")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	body, _ := json.Marshal(struct {
		Op  string `json:"op"`
		Key []byte `json:"key"`
	}{"initialize", key})
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response[:n], []byte(`"ok"`)) {
		t.Fatalf("legacy initialization: %s", response[:n])
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	path := "/run/tinfoil/volumedata/legacy"
	if err := os.WriteFile(path+"/legacy-data", []byte("existing volume"), 0600); err != nil {
		t.Fatal(err)
	}
	// The previous worker owns an ext4 mount over a shared bind mount.
	if err := unix.Unmount(path, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unmount(path, 0); err != nil {
		t.Fatal(err)
	}
	control, err := devicemapper.OpenControl()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	for _, name := range []string{"tinfoil-volume-legacy", "tinfoil-volume-legacy-integrity"} {
		if err := devicemapper.Remove(control, name); err != nil {
			t.Fatal(err)
		}
	}
	d := disk("legacy", config.VolumeUnlock{Runtime: "operator"})
	d.Device, err = device.DiskSelector(packCount, 1)
	if err != nil {
		t.Fatal(err)
	}
	d.Disk.Initialize = "never"
	d.Disk.Owner = 1000
	r, err := prepareVolume(t.Context(), d, key, nil)
	if err != nil {
		if r != nil {
			_ = r.Close()
		}
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Publish(nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(d.Target + "/legacy-data")
	if err != nil || string(data) != "existing volume" {
		t.Fatalf("legacy disk roundtrip: %q %v", data, err)
	}
	t.Log("opened disk initialized by the existing cvmimage volumeworker")
}
