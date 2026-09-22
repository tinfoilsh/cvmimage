package volume

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"tinfoil/internal/boot"
)

const (
	maxRequestBytes = 64 << 10
	requestTimeout  = 5 * time.Second
	opUnlock        = 'u'
	opInitialize    = 'i'
	statusOK        = "ok"
	statusRejected  = "rejected"
	statusFailed    = "failed"
)

func Serve(ctx context.Context, parsed Spec) error {
	instance, err := openVolume(parsed)
	if err != nil {
		return err
	}
	defer instance.closeDevices()

	mounted, err := instance.prepare()
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}

	listener, err := listen(instance.socketPath(), instance.Owner)
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		err = instance.serve(ctx, connection)
		if err != nil {
			log.Printf("volume %q request failed: %v", instance.Name, err)
		}
		if instance.unlocked {
			return err
		}
	}
}

func (w *volume) socketPath() string {
	return filepath.Join(w.controlDir(), boot.VolumeSocketName)
}

func (w *volume) serve(ctx context.Context, connection *net.UnixConn) error {
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	var packet [maxRequestBytes + 1]byte
	defer clear(packet[:])
	n, err := connection.Read(packet[:])
	if err != nil {
		return err
	}
	status, requestErr := w.handle(ctx, packet[:n])
	// Set after handle, which formats a fresh volume and takes minutes on a large one.
	if err := connection.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
		return errors.Join(requestErr, err)
	}
	if _, err := connection.Write([]byte(status)); err != nil {
		return errors.Join(requestErr, err)
	}
	return requestErr
}

// A request is one datagram: a format version byte, an op byte, then the raw key.
func (w *volume) handle(ctx context.Context, packet []byte) (string, error) {
	if len(packet) < 2 || len(packet) > maxRequestBytes {
		return statusRejected, fmt.Errorf("request is %d bytes", len(packet))
	}
	version, op, key := packet[0], packet[1], packet[2:]
	if version != VersionHKDF && version != VersionArgon2 {
		return statusRejected, fmt.Errorf("unsupported volume format %d", version)
	}
	if op != opUnlock && op != opInitialize {
		return statusRejected, fmt.Errorf("invalid request operation %q", op)
	}
	if len(key) < MinKeyBytes {
		return statusRejected, fmt.Errorf("key is %d bytes, want at least %d", len(key), MinKeyBytes)
	}
	if op == opInitialize {
		blank, err := blockDeviceBlank(w.source)
		if err != nil {
			return statusFailed, err
		}
		if !blank {
			return statusRejected, errors.New("storage volume is not blank")
		}
	}
	if err := w.activate(ctx, key, op == opInitialize, version); err != nil {
		return statusFailed, err
	}
	w.unlocked = true
	return statusOK, nil
}

func listen(path string, owner int) (*net.UnixListener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	if err := os.Chown(path, owner, owner); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
