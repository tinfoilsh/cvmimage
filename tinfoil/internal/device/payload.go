package device

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// readDiskPayload reads a NUL-padded config disk without reading its full
// capacity into memory. Embedded non-NUL bytes after padding are rejected.
func ReadDiskPayload(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if padding := bytes.IndexByte(data, 0); padding >= 0 {
		for _, value := range data[padding:] {
			if value != 0 {
				return nil, fmt.Errorf("%s contains data after NUL padding", path)
			}
		}
		return data[:padding], nil
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s payload exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}
