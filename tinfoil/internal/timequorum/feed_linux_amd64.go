package timequorum

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"time"
)

const (
	chronySampleMagic = 0x534f434b
)

// ChronyFeed writes to a connected socket supplied by PID 1, without granting
// the serving process permission to create other Unix sockets or set time.
type ChronyFeed struct{ connection *net.UnixConn }

// InheritChronyFeed takes ownership of fd.
func InheritChronyFeed(fd int) (*ChronyFeed, error) {
	if fd < 0 {
		return nil, errors.New("missing inherited time feed")
	}
	file := os.NewFile(uintptr(fd), "time-feed")
	if file == nil {
		return nil, errors.New("invalid time feed descriptor")
	}
	defer file.Close()
	connection, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok || unix.RemoteAddr() == nil || unix.RemoteAddr().Network() != "unixgram" {
		connection.Close()
		return nil, errors.New("time feed must be a connected Unix datagram socket")
	}
	return &ChronyFeed{connection: unix}, nil
}

func (feed *ChronyFeed) Close() error { return feed.connection.Close() }

type chronySample struct {
	Seconds      int64
	Microseconds int64
	Offset       float64
	Pulse        int32
	Leap         int32
	Padding      int32
	Magic        int32
}

func (feed *ChronyFeed) Send(ctx context.Context, agreement Agreement) error {
	now := time.Now()
	age := now.Sub(agreement.Observed)
	if agreement.UTC.IsZero() || agreement.Observed.IsZero() || age < 0 || age > MaxSampleAge || len(agreement.Operators) < RequiredOperators {
		return errors.New("invalid authenticated time agreement")
	}
	target := agreement.UTC.Add(age)
	packet := chronySample{Seconds: now.Unix(), Microseconds: int64(now.Nanosecond()) / int64(time.Microsecond),
		Offset: float64(target.Unix()-now.Unix()) + float64(target.Nanosecond()-now.Nanosecond())/float64(time.Second),
		Leap:   int32(agreement.Leap), Magic: chronySampleMagic}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.NativeEndian, packet); err != nil {
		return err
	}
	deadline := now.Add(FeedLimit)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := feed.connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err := feed.connection.Write(data.Bytes())
	return err
}
