package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
)

func bootLogf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	log.Print(message)
	writeKmsg(message)
}

func writeKmsg(message string) {
	message = strings.TrimRight(message, "\n")
	if message == "" {
		return
	}

	file, err := os.OpenFile("/dev/kmsg", os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		_, _ = fmt.Fprintf(file, "<6>tinfoil-boot: %s\n", message)
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
