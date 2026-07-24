package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
)

const (
	directoryMode = 0040000 | 0755
	regularMode   = 0100000 | 0755
	symlinkMode   = 0120000 | 0777
)

type entry struct {
	name  string
	mode  uint32
	nlink uint32
	data  []byte
}

func pad(buffer *bytes.Buffer, alignment int) {
	padding := (alignment - buffer.Len()%alignment) % alignment
	buffer.Write(make([]byte, padding))
}

func appendEntry(buffer *bytes.Buffer, inode uint32, item entry) error {
	if len(item.data) > math.MaxUint32 {
		return fmt.Errorf("%s exceeds newc size limit", item.name)
	}
	name := append([]byte(item.name), 0)
	header := fmt.Sprintf(
		"070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		inode, item.mode, 0, 0, item.nlink, 0, len(item.data), 0, 0, 0, 0, len(name), 0,
	)
	if len(header) != 110 {
		return fmt.Errorf("invalid newc header length for %s", item.name)
	}
	buffer.WriteString(header)
	buffer.Write(name)
	pad(buffer, 4)
	buffer.Write(item.data)
	pad(buffer, 4)
	return nil
}

func fixedArchive(binary []byte) ([]byte, error) {
	entries := []entry{
		{name: "dev", mode: directoryMode, nlink: 2},
		{name: "init", mode: symlinkMode, nlink: 1, data: []byte("usr/bin/tinfoil-initrd")},
		{name: "proc", mode: directoryMode, nlink: 2},
		{name: "run", mode: directoryMode, nlink: 2},
		{name: "sys", mode: directoryMode, nlink: 2},
		{name: "usr", mode: directoryMode, nlink: 2},
		{name: "usr/bin", mode: directoryMode, nlink: 2},
		{name: "usr/bin/tinfoil-initrd", mode: regularMode, nlink: 1, data: binary},
	}
	var archive bytes.Buffer
	for index, item := range entries {
		if err := appendEntry(&archive, uint32(index+1), item); err != nil {
			return nil, err
		}
	}
	if err := appendEntry(&archive, uint32(len(entries)+1), entry{name: "TRAILER!!!", nlink: 1}); err != nil {
		return nil, err
	}
	pad(&archive, 512)
	return archive.Bytes(), nil
}

func run(binaryPath, zstdPath, outputPath string) error {
	metadata, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("stat initrd binary: %w", err)
	}
	if !metadata.Mode().IsRegular() {
		return fmt.Errorf("initrd binary is not a regular file: %s", binaryPath)
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read initrd binary: %w", err)
	}
	archive, err := fixedArchive(binary)
	if err != nil {
		return fmt.Errorf("write fixed initrd: %w", err)
	}
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("create initrd output: %w", err)
	}
	command := exec.Command(zstdPath, "-q", "-T1", "-19", "--no-progress", "-c")
	command.Stdin = bytes.NewReader(archive)
	command.Stdout = output
	command.Stderr = os.Stderr
	compressErr := command.Run()
	closeErr := output.Close()
	if compressErr != nil {
		return fmt.Errorf("compress fixed initrd: %w", compressErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close initrd output: %w", closeErr)
	}
	return nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s TINFOIL_INITRD ZSTD OUTPUT\n", os.Args[0])
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintf(os.Stderr, "fixed initrd: %v\n", err)
		os.Exit(1)
	}
}
