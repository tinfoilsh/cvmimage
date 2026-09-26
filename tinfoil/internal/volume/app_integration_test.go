package volume

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	appSourceEnv = "TINFOIL_VOLUME_APP_SOURCE"
	appTargetEnv = "TINFOIL_VOLUME_APP_TARGET"
	appPayload   = "persistent volume write, not the RAM placeholder\n"
	appLifetime  = 5 * time.Minute
)

type appReply struct {
	ReadOnly bool
	EROFS    bool
	Error    string
}

type volumeApp struct {
	t      *testing.T
	input  *json.Encoder
	output *json.Decoder
}

func startVolumeApp(t *testing.T, source, target string) *volumeApp {
	t.Helper()
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), appLifetime)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVolumeApp$")
	cmd.Env = []string{appSourceEnv + "=" + source, appTargetEnv + "=" + target}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := input.Close(); err != nil {
			t.Error(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Error(err)
		}
	})
	app := &volumeApp{t: t, input: json.NewEncoder(input), output: json.NewDecoder(output)}
	var ready appReply
	if err := app.output.Decode(&ready); err != nil || ready.Error != "" {
		t.Fatalf("app bind setup: %+v, %v", ready, err)
	}
	return app
}

func (app *volumeApp) check(phase string, locked bool) {
	app.t.Helper()
	if err := app.input.Encode(phase); err != nil {
		app.t.Fatal(err)
	}
	var reply appReply
	if err := app.output.Decode(&reply); err != nil {
		app.t.Fatal(err)
	}
	app.t.Logf("%s: root app readonly=%t EROFS=%t error=%q", phase, reply.ReadOnly, reply.EROFS, reply.Error)
	if reply.Error != "" || reply.ReadOnly != locked || reply.EROFS != locked {
		app.t.Errorf("%s: unexpected app reply %+v, want locked=%t", phase, reply, locked)
	}
}

func TestVolumeApp(t *testing.T) {
	source, target := os.Getenv(appSourceEnv), os.Getenv(appTargetEnv)
	if source == "" || target == "" {
		t.Skip("helper subprocess for isolated mount and VM tests")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", target, "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	// Keep DAC_OVERRIDE to prove the guard is a mount restriction, not directory permissions.
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	caps[0].Effective = 1 << unix.CAP_DAC_OVERRIDE
	caps[0].Permitted = caps[0].Effective
	if err := unix.Capset(&header, &caps[0]); err != nil {
		t.Fatal(err)
	}
	encoder, decoder := json.NewEncoder(os.Stdout), json.NewDecoder(os.Stdin)
	if err := encoder.Encode(appReply{}); err != nil {
		t.Fatal(err)
	}
	for {
		var phase string
		if err := decoder.Decode(&phase); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatal(err)
		}
		var info unix.Statfs_t
		if err := unix.Statfs(target, &info); err != nil {
			t.Fatal(err)
		}
		reply := appReply{ReadOnly: info.Flags&unix.ST_RDONLY != 0}
		file, err := os.OpenFile(filepath.Join(target, "payload"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			_, err = file.WriteString(appPayload)
			err = errors.Join(err, file.Sync(), file.Close())
		}
		reply.EROFS = errors.Is(err, unix.EROFS)
		if err != nil && !reply.EROFS {
			reply.Error = err.Error()
		}
		if err := encoder.Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
}
