package devicemapper

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func testIntegrityKey() []byte { return bytes.Repeat([]byte{0x32}, IntegrityKeyBytes) }

func testIntegrityHeader(t *testing.T, sectors uint64, key []byte) ([]byte, integrityLayout) {
	t.Helper()
	l, err := fixedIntegrityLayout(sectors)
	if err != nil {
		t.Fatal(err)
	}
	h := make([]byte, integrityHeaderBytes)
	// Encode the expected Linux v5 profile independently of the production
	// header builder. Kernel integration also checks a freshly formatted image.
	copy(h, "integrt\x00")
	h[8], h[9], h[28], h[29] = 5, 15, 3, l.bitmapLog
	binary.LittleEndian.PutUint16(h[10:12], 48)
	binary.LittleEndian.PutUint32(h[12:16], l.journalSections)
	binary.LittleEndian.PutUint64(h[16:24], l.dataSectors)
	binary.LittleEndian.PutUint32(h[24:28], 0x19)
	copy(h[48:64], []byte("test-volume-salt"))
	signTestIntegrityHeader(h, key)
	return h, l
}

func signTestIntegrityHeader(h, key []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(h[:integrityMACOffset])
	copy(h[integrityMACOffset:512], mac.Sum(nil))
}

func TestIntegrityHeaderAuthenticationAndPolicy(t *testing.T) {
	key := testIntegrityKey()
	header, layout := testIntegrityHeader(t, 64*1024*1024/512, key)
	got, err := fixedIntegrityHeader(header, key, layout)
	if err != nil || !bytes.Equal(got, header) {
		t.Fatalf("fixed header differs from the expected format: %v", err)
	}
	reject := func(snapshot, key []byte, layout integrityLayout) {
		t.Helper()
		if got, err := fixedIntegrityHeader(snapshot, key, layout); err == nil || got != nil {
			t.Fatal("invalid header or key returned usable header bytes")
		}
	}
	reject(header, bytes.Repeat([]byte{0x33}, IntegrityKeyBytes), layout)
	// Test every byte of the snapshot against the Go validator only. This
	// exercises authentication and zero-reserved checks, not kernel parsing
	// of malformed superblocks.
	for offset := range header {
		changed := bytes.Clone(header)
		changed[offset] ^= 1
		if got, err := fixedIntegrityHeader(changed, key, layout); err == nil || got != nil {
			t.Fatalf("modified header byte %d accepted", offset)
		}
	}
	// Even with a correct MAC, every byte other than salt/MAC must equal Go's
	// profile. This includes magic, geometry, version, flags and all padding.
	for offset := range header {
		if offset >= 48 && offset < 64 || offset >= integrityMACOffset && offset < 512 {
			continue
		}
		changed := bytes.Clone(header)
		changed[offset] ^= 1
		signTestIntegrityHeader(changed, key)
		if got, err := fixedIntegrityHeader(changed, key, layout); err == nil || got != nil {
			t.Fatalf("authenticated but unsupported profile at byte %d accepted", offset)
		}
	}
	for _, version := range []byte{0, 1, 2, 3, 4, 6, 255} {
		changed := bytes.Clone(header)
		changed[8] = version
		signTestIntegrityHeader(changed, key)
		reject(changed, key, layout)
	}
	reject(header[:64], key, layout)
	reject(append(bytes.Clone(header), 0), key, layout)
	reject(header, key[:16], layout)
	reject(make([]byte, integrityHeaderBytes), key, layout)
	larger, err := fixedIntegrityLayout(128 * 1024 * 1024 / 512)
	if err != nil {
		t.Fatal(err)
	}
	reject(header, key, larger)
}

func TestIntegrityHeaderRetainsOnlyAuthenticatedSalt(t *testing.T) {
	key := testIntegrityKey()
	for _, saltByte := range []byte{0, 0x53, 0xff} {
		snapshot, layout := testIntegrityHeader(t, 131072, key)
		copy(snapshot[48:64], bytes.Repeat([]byte{saltByte}, 16))
		signTestIntegrityHeader(snapshot, key)
		want := bytes.Clone(snapshot)
		got, err := fixedIntegrityHeader(snapshot, key, layout)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("authenticated salt was not retained: %v", err)
		}
		// Kernel-facing bytes must be freshly built, not an alias of the input.
		clear(snapshot)
		if !bytes.Equal(got, want) {
			t.Fatal("fixed header aliases the original snapshot")
		}
	}
}

func TestFixedIntegrityLayoutCapacity(t *testing.T) {
	// Pin the journal policy independently of production-derived expectations.
	l, err := fixedIntegrityLayout(131072)
	if err != nil || l != (integrityLayout{journalSectors: 1024, journalSections: 3, dataSectors: 128736, bitmapLog: 12}) {
		t.Fatalf("unexpected 64 MiB layout: %+v: %v", l, err)
	}
	// Covers partial metadata runs, journal-size transitions and very large
	// capacities. Validate maximal fit independently of the sizing algorithm.
	for _, sectors := range []uint64{1024, 32767, 32768, 32769, 131072, 2 << 20, 32 << 20, 1 << 35, (1<<63 - 1) / 512} {
		l, err := fixedIntegrityLayout(sectors)
		if err != nil {
			t.Fatalf("size %d: %v", sectors, err)
		}
		end := func(data uint64) uint64 {
			return 8 + uint64(l.journalSections)*264 + data + ((data+32767)/32768)*384
		}
		if l.dataSectors%8 != 0 || end(l.dataSectors) > sectors || end(l.dataSectors+8) <= sectors {
			t.Fatalf("size %d: capacity %d is not the maximal aligned fit", sectors, l.dataSectors)
		}
	}
	for _, sectors := range []uint64{0, 1, 8, 656, 657, 1 << 63, ^uint64(0)} {
		if _, err := fixedIntegrityLayout(sectors); err == nil {
			t.Fatalf("unsupported size %d accepted", sectors)
		}
	}
}

func TestIntegrityTablesPinProfileAndExcludeRawHeader(t *testing.T) {
	key := testIntegrityKey()
	_, l := testIntegrityHeader(t, 131072, key)
	params, err := integrityTable("253:2", key, l)
	if err != nil {
		t.Fatal(err)
	}
	want := "253:2 0 48 J 9 block_size:4096 fix_padding fix_hmac journal_sectors:1024 interleave_sectors:32768 buffer_sectors:128 journal_watermark:50 commit_time:10000 journal_mac:hmac(sha256):" + hex.EncodeToString(key)
	if string(params) != want {
		t.Fatal("integrity table does not pin the expected profile")
	}
	for _, bad := range []string{"", "7:0 other", "7:0\x00", "-1:0", "7:0:1", "07:0"} {
		if _, err := integrityTable(bad, key, l); err == nil {
			t.Fatal("invalid device accepted")
		}
	}
	buf, err := integrityBackingTable("test-source", "7:1", "7:2", 131072)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIOCTLRequest(buf, 2); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(buf[20:24]) != 2 {
		t.Fatal("expected two linear extents")
	}
	position := ioctlSize
	for index, want := range []struct {
		start, length uint64
		params        string
	}{{0, 8, "7:1 0"}, {8, 131064, "7:2 8"}} {
		spec := buf[position:]
		if binary.LittleEndian.Uint64(spec[:8]) != want.start || binary.LittleEndian.Uint64(spec[8:16]) != want.length || cString(spec[24:40]) != "linear" || cString(spec[40:]) != want.params {
			t.Fatalf("wrong header backing extent %d", index)
		}
		position += int(binary.LittleEndian.Uint32(spec[20:24]))
	}
	if position != len(buf) {
		t.Fatal("invalid target chain length")
	}
	if _, err := integrityBackingTable("test-source", "7:1", "7:1", 131072); err == nil {
		t.Fatal("same header and data device accepted")
	}
}
