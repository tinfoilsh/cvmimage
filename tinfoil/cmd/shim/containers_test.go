package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestServeContainerStatusFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "container-status.json")
	if err := os.WriteFile(path, []byte(`{"containers":[]}`), 0o644); err != nil {
		t.Fatalf("writing status: %v", err)
	}

	handler := serveContainerStatusFile(path)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-containers", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if got := rec.Body.String(); got != `{"containers":[]}` {
		t.Fatalf("body = %q", got)
	}
}

func TestServeContainerStatusFileMissing(t *testing.T) {
	handler := serveContainerStatusFile(filepath.Join(t.TempDir(), "missing.json"))
	req := httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-containers", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}
