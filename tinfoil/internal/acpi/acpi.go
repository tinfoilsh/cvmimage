package acpi

import (
	"archive/tar"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"tinfoil/internal/auth"
	"tinfoil/internal/config"
)

var acpiFiles = []struct {
	Path string
	Name string
}{
	{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/tables/raw", Name: "acpi_tables.bin"},
	{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/rsdp/raw", Name: "rsdp.bin"},
	{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/table-loader/raw", Name: "table_loader.bin"},
}

func buildArchive() ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, af := range acpiFiles {
		data, err := os.ReadFile(af.Path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", af.Name, err)
		}
		hdr := &tar.Header{Name: af.Name, Mode: 0o644, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("writing header for %s: %w", af.Name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("writing %s: %w", af.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("closing tar: %w", err)
	}
	return buf.Bytes(), nil
}

// HandleQemuACPI serves the QEMU fw_cfg ACPI tables as a tar archive.
//
// The archive is built once from /sys/firmware/qemu_fw_cfg on the first
// successful request and then served from an in-memory cache; the previous
// implementation persisted it to disk under cfg.CacheDir, which is no longer
// necessary now that the cache dir is private and writable only by the shim.
//
// Build errors are not cached, so a transient failure on the first request
// won't permanently poison the endpoint.
func HandleQemuACPI(_ *config.Config, externalConfig *config.ExternalConfig) http.HandlerFunc {
	var (
		mu      sync.Mutex
		archive []byte
	)
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.RequireBearer(externalConfig.ACPIAPIKey, w, r) {
			return
		}

		mu.Lock()
		if archive == nil {
			data, err := buildArchive()
			if err != nil {
				mu.Unlock()
				http.Error(w, fmt.Sprintf("Failed to build ACPI archive: %v", err), http.StatusInternalServerError)
				return
			}
			archive = data
		}
		body := archive
		mu.Unlock()

		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", `attachment; filename="acpi.tar"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}
}
