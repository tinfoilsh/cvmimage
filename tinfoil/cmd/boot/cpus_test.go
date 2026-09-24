package main

import (
	"os"
	"path/filepath"
	"testing"
)

func fakeCPURoot(t *testing.T, present string, count int) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "present"), []byte(present+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for id := 1; id < count; id++ {
		dir := filepath.Join(root, "cpu"+string(rune('0'+id)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "online"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestEnforceCPUCountOfflinesTheSurplus(t *testing.T) {
	root := fakeCPURoot(t, "0-7", 8)
	detail, err := enforceCPUCount(root, 2)
	if err != nil {
		t.Fatalf("enforceCPUCount: %v", err)
	}
	if detail != "2 of 8 CPUs online" {
		t.Fatalf("detail = %q", detail)
	}
	for id := 1; id < 8; id++ {
		state, err := os.ReadFile(filepath.Join(root, "cpu"+string(rune('0'+id)), "online"))
		if err != nil {
			t.Fatal(err)
		}
		want := "1\n"
		if id >= 2 {
			want = "0\n"
		}
		if string(state) != want {
			t.Fatalf("cpu%d online = %q, want %q", id, state, want)
		}
	}
}

func TestEnforceCPUCountFailsClosed(t *testing.T) {
	root := fakeCPURoot(t, "0-7", 8)
	for _, requested := range []int{0, -1, 9} {
		if _, err := enforceCPUCount(root, requested); err == nil {
			t.Fatalf("enforceCPUCount(%d) was accepted", requested)
		}
	}
}

func TestPresentCPUsParsesRanges(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "present"), []byte("0,2-3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ids, err := presentCPUs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || ids[0] != 0 || ids[1] != 2 || ids[2] != 3 {
		t.Fatalf("ids = %v", ids)
	}
}
