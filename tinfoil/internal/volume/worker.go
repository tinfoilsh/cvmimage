package volume

import (
	"bytes"
	"context"
	"encoding/json"
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
	maxRequestBytes = 512
	requestTimeout  = 5 * time.Second
	opStatus        = "status"
	opUnlock        = "unlock"
	opInitialize    = "initialize"
	statusOK        = "ok"
	statusRejected  = "rejected"
	statusFailed    = "failed"
	statusLocked    = "locked"
)

// request is one JSON object per SOCK_SEQPACKET datagram. The overlay layout is
// measured and reaches the worker through its invocation, so the caller supplies
// only the operation and the unlock key.
type request struct {
	Op  string `json:"op"`
	Key []byte `json:"key,omitempty"`
}

type response struct {
	Status string `json:"status"`
}

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
	reply, err := json.Marshal(response{Status: status})
	if err != nil {
		return errors.Join(requestErr, err)
	}
	// Set after handle, which formats a fresh volume and takes minutes on a large one.
	if err := connection.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
		return errors.Join(requestErr, err)
	}
	if _, err := connection.Write(reply); err != nil {
		return errors.Join(requestErr, err)
	}
	return requestErr
}

func (w *volume) handle(ctx context.Context, packet []byte) (string, error) {
	if len(packet) > maxRequestBytes {
		return statusRejected, errors.New("request is too large")
	}
	var spec request
	defer func() { clear(spec.Key) }()
	decoder := json.NewDecoder(bytes.NewReader(packet))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return statusRejected, err
	}
	if spec.Op == opStatus {
		return statusLocked, nil
	}
	if spec.Op != opUnlock && spec.Op != opInitialize {
		return statusRejected, fmt.Errorf("invalid request operation %q", spec.Op)
	}
	if len(spec.Key) != KeyBytes {
		return statusRejected, fmt.Errorf("key is %d bytes, want %d", len(spec.Key), KeyBytes)
	}
	if spec.Op == opInitialize {
		blank, err := blockDeviceBlank(w.source)
		if err != nil {
			return statusFailed, err
		}
		if !blank {
			return statusRejected, errors.New("storage volume is not blank")
		}
	}
	if err := w.activate(ctx, spec.Key, spec.Op == opInitialize, true); err != nil {
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
