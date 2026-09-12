package modelpack

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tinfoilsh/modelwrap"
)

func testSource(encrypted bool) Source {
	return Source{Ref: strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36", Repo: "org/model@revision", Encrypted: encrypted}
}

type fakeMapping struct {
	path   string
	number uint64
	close  func() error
}

func (m *fakeMapping) Path() string         { return m.path }
func (m *fakeMapping) DeviceNumber() uint64 { return m.number }
func (m *fakeMapping) Close() error         { return m.close() }

type fakePackOps struct {
	events    []string
	fail      string
	busy      string
	key       []byte
	keyBefore []byte
	salt      []byte
}

func (f *fakePackOps) acquire(kind string) (mapping, error) {
	f.events = append(f.events, "open:"+kind)
	if f.fail == kind+"-create" {
		return nil, errors.New("creation failed")
	}
	number := uint64(1)
	if kind == "verity" {
		number = 2
	}
	m := &fakeMapping{number: number, path: "/dev/mapper/" + kind, close: func() error {
		f.events = append(f.events, "close:"+kind)
		if f.busy == kind {
			return errors.New("busy")
		}
		return nil
	}}
	if f.fail == kind+"-load" {
		return m, errors.New("table load failed")
	}
	return m, nil
}
func (f *fakePackOps) openCrypt(_, _ string, key []byte) (mapping, error) {
	f.key = key
	f.keyBefore = bytes.Clone(key)
	return f.acquire("crypt")
}
func (f *fakePackOps) openVerity(_ string, _ *modelwrap.ArtifactRef, salt []byte) (mapping, error) {
	f.salt = bytes.Clone(salt)
	return f.acquire("verity")
}
func TestOpenBorrowsMasterKeyAndErasesDerivedKey(t *testing.T) {
	source := testSource(true)
	key := bytes.Repeat([]byte{0x71}, modelwrap.EMWPMasterKeyBytes)
	before := bytes.Clone(key)
	ops := &fakePackOps{}
	pack, err := openPack(ops, source, "/dev/source", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pack.Close(); err != nil {
			t.Error(err)
		}
	})
	ref, _ := modelwrap.ParseRef(source.Ref)
	want, err := modelwrap.DeriveKey(key, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !bytes.Equal(ops.keyBefore, want) || !bytes.Equal(ops.key, make([]byte, len(want))) || !bytes.Equal(key, before) {
		t.Fatal("key ownership or derivation changed")
	}
	if !bytes.Equal(ops.salt, modelwrap.VeritySalt(source.Repo)) {
		t.Fatal("verity salt changed")
	}
}

func TestOpenReturnsEveryPartialResource(t *testing.T) {
	for _, tt := range []struct {
		fail   string
		closed []string
	}{
		{"crypt-create", nil},
		{"crypt-load", []string{"close:crypt"}},
		{"verity-create", []string{"close:crypt"}},
		{"verity-load", []string{"close:verity", "close:crypt"}},
	} {
		t.Run(tt.fail, func(t *testing.T) {
			ops := &fakePackOps{fail: tt.fail}
			pack, err := openPack(ops, testSource(true), "/dev/source", make([]byte, 64))
			if err == nil || pack == nil {
				t.Fatalf("partial open: %v, %v", pack, err)
			}
			if !bytes.Equal(ops.key, make([]byte, len(ops.key))) {
				t.Fatal("failed open retained the derived key")
			}
			ops.events = nil
			if err := pack.Close(); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ops.events, tt.closed) {
				t.Fatalf("cleanup = %v, want %v", ops.events, tt.closed)
			}
			if err := pack.Close(); err != nil || !slices.Equal(ops.events, tt.closed) {
				t.Fatal("repeated completed cleanup")
			}
		})
	}
}

func TestCloseResumesAfterMappingFailure(t *testing.T) {
	ops := &fakePackOps{busy: "verity"}
	pack, err := openPack(ops, testSource(true), "/dev/source", make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	ops.events = nil
	if err := pack.Close(); err == nil {
		t.Fatal("expected busy mapping")
	}
	if !slices.Equal(ops.events, []string{"close:verity"}) {
		t.Fatal(ops.events)
	}
	ops.busy = ""
	if err := pack.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"close:verity", "close:verity", "close:crypt"}
	if !slices.Equal(ops.events, want) {
		t.Fatalf("cleanup did not resume: %v", ops.events)
	}
}

func TestOpenReturnsVerityDevice(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		var key []byte
		if encrypted {
			key = make([]byte, 64)
		}
		ops := &fakePackOps{}
		device, err := openPack(ops, testSource(encrypted), "/dev/source", key)
		if err != nil {
			t.Fatal(err)
		}
		if device.Path() != "/dev/mapper/verity" || device.DeviceNumber() != 2 {
			t.Fatal("returned a device other than the verified mapping")
		}
		if err := device.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
