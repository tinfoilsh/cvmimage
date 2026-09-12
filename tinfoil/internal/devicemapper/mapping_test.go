package devicemapper

import (
	"errors"
	"slices"
	"testing"
)

func TestFailedCreationDoesNotOwnExistingMapping(t *testing.T) {
	removed := false
	m, err := createMapping("existing", func() error { return errors.New("exists") }, func(string) error { removed = true; return nil })
	if err == nil || m != nil {
		t.Fatal("failed creation returned ownership")
	}
	if err := m.Close(); err != nil || removed {
		t.Fatal("removed an unowned mapping")
	}
}

func TestCloseResumesAfterKernelRemoval(t *testing.T) {
	var events []string
	busy := true
	m := &Mapping{name: "owned", remove: func(string) error {
		events = append(events, "kernel")
		return nil
	}, removeNode: func(string) error {
		events = append(events, "node")
		if busy {
			return errors.New("node removal failed")
		}
		return nil
	}}
	if err := m.Close(); err == nil {
		t.Fatal("expected node removal failure")
	}
	busy = false
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil || !slices.Equal(events, []string{"kernel", "node", "node"}) {
		t.Fatalf("cleanup repeated kernel removal: %v, %v", events, err)
	}
}

func TestMappingCloseRetainsOwnershipUntilRemoval(t *testing.T) {
	busy := true
	calls := 0
	m, err := createMapping("owned", func() error { return nil }, func(name string) error {
		calls++
		if name != "owned" {
			t.Fatal(name)
		}
		if busy {
			return errors.New("busy")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err == nil {
		t.Fatal("expected busy")
	}
	busy = false
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil || calls != 2 {
		t.Fatalf("close repeated removal: calls=%d err=%v", calls, err)
	}
}
