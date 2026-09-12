package volume

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitReturnsOnlyRequestedReadyVolumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "volumes.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Snapshot{Volumes: []Status{{Name: "ready", Phase: "ready", Path: "/resolved/location", Access: "ro"}, {Name: "locked", Phase: "locked", Access: "rw"}}})
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got, err := (Client{Socket: path}).Wait(ctx, []string{"ready", "ready"})
	if err != nil || len(got) != 1 || got["ready"] != (ReadyVolume{Path: "/resolved/location", Access: "ro"}) {
		t.Fatalf("resolved mounts: %v, %v", got, err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := (Client{Socket: path}).Wait(ctx, []string{"locked"}); err == nil {
		t.Fatal("locked dependency did not wait")
	}
}

func TestResolveReadyRejectsUnavailableOrInvalidMounts(t *testing.T) {
	for _, status := range []Status{
		{Name: "other", Phase: "ready", Path: "/volume", Access: "rw"},
		{Name: "state", Phase: "failed"}, {Name: "state", Phase: "closed"},
		{Name: "state", Phase: "ready", Access: "rw"},
		{Name: "state", Phase: "ready", Path: "relative", Access: "rw"},
		{Name: "state", Phase: "ready", Path: "/volume", Access: "unknown"},
	} {
		if _, _, err := resolveReady(Snapshot{Volumes: []Status{status}}, []string{"state"}); err == nil {
			t.Fatalf("accepted %+v", status)
		}
	}
}
