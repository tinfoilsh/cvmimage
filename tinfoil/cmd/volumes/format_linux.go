package main

import (
	"errors"
	"regexp"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"

	"tinfoil/internal/volume"
)

var formatterDevicePattern = regexp.MustCompile(`^/dev/mapper/tinfoil-volume-[a-z][a-z0-9-]{0,62}$`)

type formatterInvocation struct {
	device string
	owner  int
}

func parseFormatter(args []string) (formatterInvocation, error) {
	if len(args) != 4 || args[1] != "--format" {
		return formatterInvocation{}, errors.New("invalid formatter invocation")
	}
	owner, err := strconv.Atoi(args[3])
	if err != nil || owner < 0 || owner > 65534 {
		return formatterInvocation{}, errors.New("invalid formatter owner")
	}
	if !formatterDevicePattern.MatchString(args[2]) {
		return formatterInvocation{}, errors.New("invalid formatter device")
	}
	return formatterInvocation{device: args[2], owner: owner}, nil
}

func runFormatter(args []string) error {
	invocation, err := parseFormatter(args)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	// Neither the layout probe nor mkfs may regain root capabilities across exec.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var empty [2]unix.CapUserData
	if err := unix.Capset(&header, &empty[0]); err != nil {
		return err
	}
	var current [2]unix.CapUserData
	if err := unix.Capget(&header, &current[0]); err != nil {
		return err
	}
	for _, data := range current {
		if data.Effective != 0 || data.Permitted != 0 || data.Inheritable != 0 {
			return errors.New("formatter retained capabilities")
		}
	}
	return volume.FormatExt4(invocation.device, invocation.owner)
}
