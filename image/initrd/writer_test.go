package main

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"
)

type archiveEntry struct {
	inode uint32
	name  string
	mode  uint32
	nlink uint32
	data  []byte
}

func parseHexField(header []byte, offset int) (uint32, error) {
	value, err := strconv.ParseUint(string(header[offset:offset+8]), 16, 32)
	return uint32(value), err
}

func parseArchive(archive []byte) ([]archiveEntry, int, error) {
	var entries []archiveEntry
	offset := 0
	for {
		if offset+110 > len(archive) {
			return nil, 0, fmt.Errorf("truncated header at offset %d", offset)
		}
		header := archive[offset : offset+110]
		if string(header[:6]) != "070701" {
			return nil, 0, fmt.Errorf("invalid magic at offset %d", offset)
		}
		inode, err := parseHexField(header, 6)
		if err != nil {
			return nil, 0, fmt.Errorf("parse inode: %w", err)
		}
		mode, err := parseHexField(header, 14)
		if err != nil {
			return nil, 0, fmt.Errorf("parse mode: %w", err)
		}
		nlink, err := parseHexField(header, 38)
		if err != nil {
			return nil, 0, fmt.Errorf("parse nlink: %w", err)
		}
		fileSize, err := parseHexField(header, 54)
		if err != nil {
			return nil, 0, fmt.Errorf("parse file size: %w", err)
		}
		nameSize, err := parseHexField(header, 94)
		if err != nil {
			return nil, 0, fmt.Errorf("parse name size: %w", err)
		}
		for fieldOffset := 22; fieldOffset <= 102; fieldOffset += 8 {
			if fieldOffset == 38 || fieldOffset == 54 || fieldOffset == 94 {
				continue
			}
			value, err := parseHexField(header, fieldOffset)
			if err != nil {
				return nil, 0, fmt.Errorf("parse metadata field: %w", err)
			}
			if value != 0 {
				return nil, 0, fmt.Errorf("nonzero fixed metadata at offset %d", fieldOffset)
			}
		}

		offset += len(header)
		nameEnd := offset + int(nameSize)
		if nameSize == 0 || nameEnd > len(archive) || archive[nameEnd-1] != 0 {
			return nil, 0, fmt.Errorf("invalid name at offset %d", offset)
		}
		name := string(archive[offset : nameEnd-1])
		offset = (nameEnd + 3) &^ 3
		dataEnd := offset + int(fileSize)
		if dataEnd > len(archive) {
			return nil, 0, fmt.Errorf("truncated data for %s", name)
		}
		entries = append(entries, archiveEntry{
			inode: inode,
			name:  name,
			mode:  mode,
			nlink: nlink,
			data:  append([]byte(nil), archive[offset:dataEnd]...),
		})
		offset = (dataEnd + 3) &^ 3
		if name == "TRAILER!!!" {
			return entries, offset, nil
		}
	}
}

func TestFixedArchiveContract(t *testing.T) {
	binary := []byte("fixed test binary\n")
	first, err := fixedArchive(binary)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixedArchive(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("repeated archives differ")
	}
	if len(first)%512 != 0 {
		t.Fatalf("archive length %d is not 512-byte aligned", len(first))
	}

	entries, trailerEnd, err := parseArchive(first)
	if err != nil {
		t.Fatal(err)
	}
	expected := []archiveEntry{
		{inode: 1, name: "dev", mode: 0040000 | 0755, nlink: 2},
		{inode: 2, name: "init", mode: 0120000 | 0777, nlink: 1, data: []byte("usr/bin/tinfoil-initrd")},
		{inode: 3, name: "proc", mode: 0040000 | 0755, nlink: 2},
		{inode: 4, name: "run", mode: 0040000 | 0755, nlink: 2},
		{inode: 5, name: "sys", mode: 0040000 | 0755, nlink: 2},
		{inode: 6, name: "usr", mode: 0040000 | 0755, nlink: 2},
		{inode: 7, name: "usr/bin", mode: 0040000 | 0755, nlink: 2},
		{inode: 8, name: "usr/bin/tinfoil-initrd", mode: 0100000 | 0755, nlink: 1, data: binary},
		{inode: 9, name: "TRAILER!!!", nlink: 1},
	}
	if len(entries) != len(expected) {
		t.Fatalf("got %d entries, want %d", len(entries), len(expected))
	}
	for index := range expected {
		if entries[index].inode != expected[index].inode ||
			entries[index].name != expected[index].name ||
			entries[index].mode != expected[index].mode ||
			entries[index].nlink != expected[index].nlink ||
			!bytes.Equal(entries[index].data, expected[index].data) {
			t.Errorf("entry %d = %+v, want %+v", index, entries[index], expected[index])
		}
	}
	if !bytes.Equal(first[trailerEnd:], make([]byte, len(first)-trailerEnd)) {
		t.Fatal("archive has nonzero trailing padding")
	}
}
