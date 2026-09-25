package main

import (
	"net"
	"os"
)

const attestationSocketMode = 0o666

func newAttestationSocket(path string) (*os.File, error) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	if err := os.Chmod(path, attestationSocketMode); err != nil {
		return nil, err
	}
	file, err := listener.File()
	if err != nil {
		return nil, err
	}
	// PID 1 retains the listener across shim restarts without granting the shim
	// permission to create Unix sockets to other host services.
	listener.SetUnlinkOnClose(false)
	return file, nil
}
