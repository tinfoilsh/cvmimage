package acpi

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tinfoil/internal/config"
)

func HandleQemuACPI(cfg *config.Config, externalConfig *config.ExternalConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if externalConfig.ACPIAPIKey != "" {
			apiKey := strings.TrimPrefix(
				r.Header.Get("Authorization"),
				"Bearer ",
			)
			if apiKey != externalConfig.ACPIAPIKey {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		var buf bytes.Buffer

		archivePath := filepath.Join(cfg.CacheDir, "acpi.tar")
		force := r.URL.Query().Get("force") == "1"

		if _, err := os.Stat(archivePath); !force && err == nil {
			data, err := os.ReadFile(archivePath)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to read ACPI archive: %v", err), http.StatusInternalServerError)
				return
			}
			_, err = buf.Write(data)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to write ACPI archive to buffer: %v", err), http.StatusInternalServerError)
				return
			}
		} else {
			tw := tar.NewWriter(&buf)
			type acpi_file struct {
				Path string
				Name string
			}
			acpi_files := []acpi_file{
				{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/tables/raw", Name: "acpi_tables.bin"},
				{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/rsdp/raw", Name: "rsdp.bin"},
				{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/table-loader/raw", Name: "table_loader.bin"},
			}

			for _, af := range acpi_files {
				data, err := os.ReadFile(af.Path)
				if err != nil {
					http.Error(w, fmt.Sprintf("Failed to read ACPI source file %s", af.Name), http.StatusInternalServerError)
					return
				}
				hdr := &tar.Header{
					Name: af.Name,
					Mode: 0644,
					Size: int64(len(data)),
				}
				if err := tw.WriteHeader(hdr); err != nil {
					http.Error(w, fmt.Sprintf("Failed to write header for ACPI source file %s", af.Name), http.StatusInternalServerError)
					return
				}
				if _, err := tw.Write(data); err != nil {
					http.Error(w, fmt.Sprintf("Failed to write ACPI source file %s", af.Name), http.StatusInternalServerError)
					return
				}
			}

			tw.Close()

			// Persist to disk
			if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err == nil {
				tmp, err := os.CreateTemp(filepath.Dir(archivePath), "acpi-*.tar")
				if err == nil {
					if _, err := io.Copy(tmp, bytes.NewReader(buf.Bytes())); err == nil {
						tmp.Close()
						_ = os.Rename(tmp.Name(), archivePath)
					} else {
						tmp.Close()
						_ = os.Remove(tmp.Name())
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(archivePath)+"\"")
		w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))

		if _, err := io.Copy(w, &buf); err != nil {
			http.Error(w, fmt.Sprintf("Failed to copy ACPI archive to response: %v", err), http.StatusInternalServerError)
			return
		}

	}
}
