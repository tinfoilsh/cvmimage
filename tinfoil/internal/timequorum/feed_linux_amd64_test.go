package timequorum

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/beevik/ntp"
	"golang.org/x/sys/unix"
)

func TestInheritedFeedEncodesNativeChronySample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	file, err := connection.File()
	connection.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	feed, err := InheritChronyFeed(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	const offset = 5 * time.Second
	now := time.Now()
	agreement := Agreement{UTC: now.Add(offset).UTC(), Observed: now, Operators: []Operator{Canonical, Cloudflare, Netnod}, Leap: ntp.LeapAddSecond}
	if err := feed.Send(context.Background(), agreement); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(chronyFeedLimit)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 128)
	n, _, err := listener.ReadFromUnix(packet)
	if err != nil {
		t.Fatal(err)
	}
	const nativeSampleBytes = 40
	if n != nativeSampleBytes {
		t.Fatalf("sample size=%d, want %d", n, nativeSampleBytes)
	}
	var sample chronySample
	if err := binary.Read(bytes.NewReader(packet[:n]), binary.NativeEndian, &sample); err != nil {
		t.Fatal(err)
	}
	if sample.Magic != chronySampleMagic || sample.Pulse != 0 || sample.Leap != int32(ntp.LeapAddSecond) || math.Abs(sample.Offset-offset.Seconds()) > time.Millisecond.Seconds() {
		t.Fatalf("invalid native sample: %+v", sample)
	}
	measured := time.Unix(sample.Seconds, sample.Microseconds*int64(time.Microsecond))
	if measured.Before(now.Truncate(time.Microsecond)) || measured.After(time.Now()) || sample.Microseconds < 0 || sample.Microseconds >= int64(time.Second/time.Microsecond) {
		t.Fatalf("invalid measurement time: %+v", sample)
	}
	if err := feed.Send(context.Background(), Agreement{}); err == nil {
		t.Fatal("unverified agreement accepted")
	}
}

func TestFeedRejectsUnconnectedOrStreamDescriptors(t *testing.T) {
	if _, err := InheritChronyFeed(-1); err == nil {
		t.Fatal("missing feed accepted")
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if feed, err := InheritChronyFeed(fd); err == nil {
		feed.Close()
		t.Fatal("unconnected feed accepted")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	if feed, err := InheritChronyFeed(pair[0]); err == nil {
		feed.Close()
		t.Fatal("stream descriptor accepted as time feed")
	}
}
