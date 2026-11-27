package volume

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseVolumeMountsDeepestFirst(t *testing.T) {
	const mountinfo = `22 1 0:21 / / rw - rootfs rootfs rw
30 22 0:25 / /run rw,nosuid - tmpfs tmpfs rw
41 30 253:1 / /run/tinfoil/volumedata/workspace rw,nodev,nosuid,noexec - ext4 /dev/mapper/tinfoil-volume-workspace rw,errors=remount-ro
42 41 0:40 / /run/tinfoil/volumedata/workspace/models/llama rw - overlay overlay rw,lowerdir=/x
43 30 253:3 / /run/tinfoil/volumedata/other\040disk rw - ext4 /dev/mapper/tinfoil-volume-other rw
44 30 0:41 / /run/tinfoil/volumedata-not-ours rw - tmpfs tmpfs rw
`
	got, err := parseVolumeMounts(strings.NewReader(mountinfo), "/run/tinfoil/volumedata")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/run/tinfoil/volumedata/workspace/models/llama",
		"/run/tinfoil/volumedata/workspace",
		"/run/tinfoil/volumedata/other disk",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
