package volume

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadOnlyExt4RequiresCleanSuperblock(t *testing.T) {
	clean := make([]byte, 2048)
	binary.LittleEndian.PutUint16(clean[1024+0x38:], 0xef53)
	binary.LittleEndian.PutUint16(clean[1024+0x3a:], 1)
	if err := checkCleanExt4(bytes.NewReader(clean)); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0x38, 0x3a, 0x60, 0xe8, 0x66} {
		dirty := bytes.Clone(clean)
		dirty[1024+offset] = 4
		if offset == 0x66 {
			dirty[1024+offset] = 1
		}
		if err := checkCleanExt4(bytes.NewReader(dirty)); err == nil {
			t.Fatalf("accepted dirty metadata at %#x", offset)
		}
	}
	if err := checkCleanExt4(bytes.NewReader(clean[:1536])); err == nil {
		t.Fatal("accepted truncated superblock")
	}
}
