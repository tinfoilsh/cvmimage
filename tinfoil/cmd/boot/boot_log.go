package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"tinfoil/internal/boot"
)

func bootLogf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	log.Print(message)
	// Under tinfoil-init, stdout/stderr are already forwarded to kmsg and the
	// console with a "tinfoil-boot:" prefix; writing again here would emit
	// every message twice. The direct path only serves standalone runs.
	if os.Getenv("TINFOIL_PID1") == "" {
		writeKmsg(message)
	}
}

func writeKmsg(message string) {
	message = strings.TrimRight(message, "\n")
	if message == "" {
		return
	}

	file, err := os.OpenFile("/dev/kmsg", os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		_, _ = fmt.Fprintf(file, boot.KmsgInfoPrefix+"tinfoil-boot: %s\n", message)
		_ = file.Close()
	}

	for _, device := range []string{"/dev/ttyS0", "/dev/console"} {
		console, err := os.OpenFile(device, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(console, "tinfoil-boot: %s\n", message)
		_ = console.Close()
	}
}
