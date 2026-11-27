package volume

import (
	"slices"
	"testing"
)

func TestMountedVolumesIncludesUnlockedFilesystemsAndTheirOverlays(t *testing.T) {
	mounts := "tmpfs " + dataRoot + "/locked tmpfs ro 0 0\n" +
		"tmpfs " + dataRoot + "/workspace tmpfs ro 0 0\n" +
		"/dev/mapper/tinfoil-volume-workspace " + dataRoot + "/workspace ext4 rw 0 0\n" +
		"overlay " + dataRoot + "/workspace/weights overlay rw 0 0\n" +
		"/dev/mapper/root / ext4 ro 0 0\n" +
		"overlay /var/lib/docker/overlay2/merged overlay rw 0 0\n"
	volumes, overlays := mountedVolumes(mounts)
	if !slices.Equal(volumes, []string{dataRoot + "/workspace"}) || !slices.Equal(overlays, []string{dataRoot + "/workspace/weights"}) {
		t.Fatalf("selected volumes %v and overlays %v", volumes, overlays)
	}
}
