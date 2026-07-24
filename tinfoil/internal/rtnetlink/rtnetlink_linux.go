package rtnetlink

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	netlinkHeaderLen = unix.NLMSG_HDRLEN
	ifInfoMessageLen = unix.SizeofIfInfomsg
	ifAddrMessageLen = unix.SizeofIfAddrmsg
	routeMessageLen  = unix.SizeofRtMsg
	routeAttrLen     = unix.SizeofRtAttr
	netlinkErrorLen  = unix.SizeofNlMsgerr

	maxDatagramBytes = 64 << 10
	maxMessageBytes  = 16 << 10
	maxRequestBytes  = 4 << 10
	maxDumpBytes     = 4 << 20
	maxFlushBytes    = 1 << 20
	requestTimeout   = 5 * time.Second
)

var nextSequence atomic.Uint32

type client struct {
	fd     int
	portID uint32
}

type netlinkMessage struct {
	header  netlinkHeader
	payload []byte
}

type netlinkHeader struct {
	length   uint32
	typeCode uint16
	flags    uint16
	sequence uint32
	portID   uint32
}

type routeAttribute struct {
	typeCode uint16
	value    []byte
}

func SetLoopbackUp(ctx context.Context) error {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("find loopback interface: %w", err)
	}
	connection, err := openClient()
	if err != nil {
		return err
	}
	defer connection.close()
	if err := connection.setLinkUp(ctx, loopback.Index); err != nil {
		return fmt.Errorf("set loopback up: %w", err)
	}
	return nil
}

func ConfigureIPv4(ctx context.Context, interfaceName string, prefix netip.Prefix, gateway netip.Addr) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return fmt.Errorf("configured prefix is not IPv4: %s", prefix)
	}
	if !gateway.IsValid() || !gateway.Is4() {
		return fmt.Errorf("configured gateway is not IPv4: %s", gateway)
	}
	device, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", interfaceName, err)
	}
	connection, err := openClient()
	if err != nil {
		return err
	}
	defer connection.close()

	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"set link up", func(ctx context.Context) error { return connection.setLinkUp(ctx, device.Index) }},
		{"flush IPv4 addresses", func(ctx context.Context) error { return connection.flushAddresses(ctx, device.Index) }},
		{"flush IPv4 routes", func(ctx context.Context) error { return connection.flushRoutes(ctx, device.Index) }},
		{"replace IPv4 prefix", func(ctx context.Context) error { return connection.replaceAddress(ctx, device.Index, prefix) }},
		{"replace default IPv4 route", func(ctx context.Context) error { return connection.replaceDefaultRoute(ctx, device.Index, gateway) }},
	}
	for _, step := range steps {
		if err := step.run(ctx); err != nil {
			return fmt.Errorf("%s on %q: %w", step.name, interfaceName, err)
		}
	}
	return nil
}

func openClient() (*client, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open NETLINK_ROUTE socket: %w", err)
	}
	connection := &client{fd: fd}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		connection.close()
		return nil, fmt.Errorf("bind NETLINK_ROUTE socket: %w", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		connection.close()
		return nil, fmt.Errorf("read NETLINK_ROUTE socket address: %w", err)
	}
	netlinkAddress, ok := address.(*unix.SockaddrNetlink)
	if !ok || netlinkAddress.Pid == 0 {
		connection.close()
		return nil, errors.New("NETLINK_ROUTE socket returned invalid port ID")
	}
	connection.portID = netlinkAddress.Pid
	return connection, nil
}

func (c *client) close() {
	_ = unix.Close(c.fd)
}

func (c *client) setLinkUp(ctx context.Context, index int) error {
	return c.requestAck(ctx, unix.RTM_NEWLINK, 0, linkUpPayload(index))
}

func linkUpPayload(index int) []byte {
	payload := make([]byte, ifInfoMessageLen)
	payload[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(payload[4:8], uint32(index))
	binary.NativeEndian.PutUint32(payload[8:12], unix.IFF_UP)
	binary.NativeEndian.PutUint32(payload[12:16], unix.IFF_UP)
	return payload
}

func (c *client) flushAddresses(ctx context.Context, index int) error {
	payload := make([]byte, ifAddrMessageLen)
	payload[0] = unix.AF_INET
	candidates, err := c.requestDump(ctx, unix.RTM_GETADDR, unix.RTM_NEWADDR, payload, func(message []byte) (bool, error) {
		return addressMatchesInterface(message, index)
	})
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := c.requestAck(ctx, unix.RTM_DELADDR, 0, candidate); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) flushRoutes(ctx context.Context, index int) error {
	payload := make([]byte, routeMessageLen)
	payload[0] = unix.AF_INET
	candidates, err := c.requestDump(ctx, unix.RTM_GETROUTE, unix.RTM_NEWROUTE, payload, func(message []byte) (bool, error) {
		return routeMatchesInterface(message, index)
	})
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := c.requestAck(ctx, unix.RTM_DELROUTE, 0, candidate); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) replaceAddress(ctx context.Context, index int, prefix netip.Prefix) error {
	return c.requestAck(ctx, unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, addressPayload(index, prefix))
}

func addressPayload(index int, prefix netip.Prefix) []byte {
	payload := make([]byte, ifAddrMessageLen)
	payload[0] = unix.AF_INET
	payload[1] = uint8(prefix.Bits())
	payload[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(payload[4:8], uint32(index))
	address := prefix.Addr().As4()
	payload = appendAttribute(payload, unix.IFA_LOCAL, address[:])
	payload = appendAttribute(payload, unix.IFA_ADDRESS, address[:])
	return payload
}

func (c *client) replaceDefaultRoute(ctx context.Context, index int, gateway netip.Addr) error {
	return c.requestAck(ctx, unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, defaultRoutePayload(index, gateway))
}

func defaultRoutePayload(index int, gateway netip.Addr) []byte {
	payload := make([]byte, routeMessageLen)
	payload[0] = unix.AF_INET
	payload[4] = unix.RT_TABLE_MAIN
	payload[5] = unix.RTPROT_BOOT
	payload[6] = unix.RT_SCOPE_UNIVERSE
	payload[7] = unix.RTN_UNICAST
	address := gateway.As4()
	payload = appendAttribute(payload, unix.RTA_GATEWAY, address[:])
	outputInterface := make([]byte, 4)
	binary.NativeEndian.PutUint32(outputInterface, uint32(index))
	payload = appendAttribute(payload, unix.RTA_OIF, outputInterface)
	return payload
}

func (c *client) requestAck(ctx context.Context, typeCode, extraFlags uint16, payload []byte) error {
	sequence := newSequence()
	request, err := encodeRequest(typeCode, unix.NLM_F_REQUEST|unix.NLM_F_ACK|extraFlags, sequence, c.portID, payload)
	if err != nil {
		return err
	}
	if err := c.send(ctx, request); err != nil {
		return err
	}
	datagram, err := c.receive(ctx)
	if err != nil {
		return err
	}
	return validateAck(datagram, request)
}

func (c *client) requestDump(
	ctx context.Context,
	requestType uint16,
	replyType uint16,
	payload []byte,
	match func([]byte) (bool, error),
) ([][]byte, error) {
	sequence := newSequence()
	request, err := encodeRequest(requestType, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, sequence, c.portID, payload)
	if err != nil {
		return nil, err
	}
	if err := c.send(ctx, request); err != nil {
		return nil, err
	}
	var candidates [][]byte
	totalBytes := 0
	dumpBytes := 0
	for {
		datagram, err := c.receive(ctx)
		if err != nil {
			return nil, err
		}
		dumpBytes += len(datagram)
		if dumpBytes > maxDumpBytes {
			return nil, errors.New("NETLINK_ROUTE dump exceeds size limit")
		}
		messages, done, err := validateDump(datagram, request, replyType)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			selected, err := match(message)
			if err != nil {
				return nil, err
			}
			if !selected {
				continue
			}
			if len(message) > maxRequestBytes-netlinkHeaderLen || totalBytes+len(message) > maxFlushBytes {
				return nil, errors.New("NETLINK_ROUTE flush candidate limit exceeded")
			}
			candidate := append([]byte(nil), message...)
			candidates = append(candidates, candidate)
			totalBytes += len(candidate)
		}
		if done {
			return candidates, nil
		}
	}
}

func (c *client) send(ctx context.Context, request []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Sendto(c.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send NETLINK_ROUTE request: %w", err)
	}
	return nil
}

func (c *client) receive(ctx context.Context) ([]byte, error) {
	deadline := time.Now().Add(requestTimeout)
	buffer := make([]byte, maxDatagramBytes)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("receive NETLINK_ROUTE reply: timeout")
		}
		receiveTimeout := min(remaining, time.Second)
		if receiveTimeout < time.Microsecond {
			receiveTimeout = time.Microsecond
		}
		timeval := unix.NsecToTimeval(receiveTimeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeval); err != nil {
			return nil, fmt.Errorf("set NETLINK_ROUTE receive timeout: %w", err)
		}
		count, _, flags, source, err := unix.Recvmsg(c.fd, buffer, nil, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, fmt.Errorf("receive NETLINK_ROUTE reply: %w", err)
		}
		if flags&unix.MSG_TRUNC != 0 || count == len(buffer) {
			return nil, errors.New("receive NETLINK_ROUTE reply: oversized datagram")
		}
		netlinkSource, ok := source.(*unix.SockaddrNetlink)
		if !ok || netlinkSource.Pid != 0 {
			return nil, errors.New("receive NETLINK_ROUTE reply: non-kernel sender")
		}
		return append([]byte(nil), buffer[:count]...), nil
	}
}

func newSequence() uint32 {
	for {
		sequence := nextSequence.Add(1)
		if sequence != 0 {
			return sequence
		}
	}
}

func encodeRequest(typeCode, flags uint16, sequence, portID uint32, payload []byte) ([]byte, error) {
	length := netlinkHeaderLen + len(payload)
	if length > maxRequestBytes {
		return nil, errors.New("NETLINK_ROUTE request exceeds size limit")
	}
	request := make([]byte, align4(length))
	binary.NativeEndian.PutUint32(request[0:4], uint32(length))
	binary.NativeEndian.PutUint16(request[4:6], typeCode)
	binary.NativeEndian.PutUint16(request[6:8], flags)
	binary.NativeEndian.PutUint32(request[8:12], sequence)
	binary.NativeEndian.PutUint32(request[12:16], portID)
	copy(request[netlinkHeaderLen:], payload)
	return request, nil
}

func appendAttribute(payload []byte, typeCode uint16, value []byte) []byte {
	length := routeAttrLen + len(value)
	start := len(payload)
	payload = append(payload, make([]byte, align4(length))...)
	binary.NativeEndian.PutUint16(payload[start:start+2], uint16(length))
	binary.NativeEndian.PutUint16(payload[start+2:start+4], typeCode)
	copy(payload[start+routeAttrLen:], value)
	return payload
}

func validateAck(datagram, request []byte) error {
	expected, err := decodeHeader(request)
	if err != nil {
		return err
	}
	messages, err := parseMessages(datagram)
	if err != nil {
		return err
	}
	if len(messages) != 1 {
		return fmt.Errorf("NETLINK_ROUTE ACK contained %d messages", len(messages))
	}
	message := messages[0]
	if err := validateReplyHeader(message.header, expected.sequence, expected.portID); err != nil {
		return err
	}
	if message.header.typeCode != unix.NLMSG_ERROR {
		return fmt.Errorf("NETLINK_ROUTE ACK has unexpected type %d or flags %#x", message.header.typeCode, message.header.flags)
	}
	if err := validateErrorFlags(message.header.flags); err != nil {
		return fmt.Errorf("NETLINK_ROUTE ACK: %w", err)
	}
	code, err := validateErrorPayload(message.payload, message.header.flags, request)
	if err != nil {
		return fmt.Errorf("NETLINK_ROUTE ACK: %w", err)
	}
	if code == 0 {
		return nil
	}
	return unix.Errno(-code)
}

func validateDump(datagram, request []byte, replyType uint16) ([][]byte, bool, error) {
	expected, err := decodeHeader(request)
	if err != nil {
		return nil, false, err
	}
	messages, err := parseMessages(datagram)
	if err != nil {
		return nil, false, err
	}
	if len(messages) == 0 {
		return nil, false, errors.New("NETLINK_ROUTE dump returned empty datagram")
	}
	var payloads [][]byte
	for index, message := range messages {
		if err := validateReplyHeader(message.header, expected.sequence, expected.portID); err != nil {
			return nil, false, err
		}
		if message.header.flags&unix.NLM_F_DUMP_INTR != 0 {
			return nil, false, errors.New("NETLINK_ROUTE dump was interrupted")
		}
		switch message.header.typeCode {
		case replyType:
			if message.header.flags != unix.NLM_F_MULTI {
				return nil, false, errors.New("NETLINK_ROUTE dump data is not multipart")
			}
			payloads = append(payloads, message.payload)
		case unix.NLMSG_DONE:
			if index != len(messages)-1 {
				return nil, false, errors.New("NETLINK_ROUTE dump terminator is not final")
			}
			if message.header.flags != unix.NLM_F_MULTI {
				return nil, false, errors.New("NETLINK_ROUTE dump terminator is not multipart")
			}
			if err := validateDonePayload(message.payload); err != nil {
				return nil, false, err
			}
			return payloads, true, nil
		case unix.NLMSG_ERROR:
			if err := validateErrorFlags(message.header.flags); err != nil {
				return nil, false, fmt.Errorf("NETLINK_ROUTE dump error: %w", err)
			}
			return nil, false, validateDumpError(message.payload, message.header.flags, request)
		default:
			return nil, false, fmt.Errorf("NETLINK_ROUTE dump has unexpected message type %d", message.header.typeCode)
		}
	}
	return payloads, false, nil
}

func validateErrorFlags(flags uint16) error {
	switch flags {
	case 0, unix.NLM_F_CAPPED:
		return nil
	default:
		return fmt.Errorf("unexpected flags %#x", flags)
	}
}

func validateReplyHeader(header netlinkHeader, sequence, portID uint32) error {
	if header.sequence != sequence || header.portID != portID {
		return errors.New("NETLINK_ROUTE reply sequence or port ID mismatch")
	}
	return nil
}

func validateDonePayload(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) != 4 {
		return fmt.Errorf("NETLINK_ROUTE dump terminator has invalid payload length %d", len(payload))
	}
	code := int32(binary.NativeEndian.Uint32(payload))
	if code == 0 {
		return nil
	}
	if code > 0 {
		return errors.New("NETLINK_ROUTE dump terminator has invalid positive error code")
	}
	return unix.Errno(-code)
}

func validateDumpError(payload []byte, flags uint16, request []byte) error {
	code, err := validateErrorPayload(payload, flags, request)
	if err != nil {
		return err
	}
	if code == 0 {
		return errors.New("NETLINK_ROUTE dump returned malformed error")
	}
	return unix.Errno(-code)
}

func validateErrorPayload(payload []byte, flags uint16, request []byte) (int32, error) {
	if len(payload) < netlinkErrorLen {
		return 0, errors.New("NETLINK_ROUTE error payload is truncated")
	}
	expected, err := decodeHeader(request)
	if err != nil {
		return 0, err
	}
	embedded, err := decodeHeader(payload[4:])
	if err != nil {
		return 0, err
	}
	if embedded != expected {
		return 0, errors.New("NETLINK_ROUTE error does not match request")
	}
	code := int32(binary.NativeEndian.Uint32(payload[:4]))
	if code > 0 {
		return 0, errors.New("NETLINK_ROUTE error contains invalid positive code")
	}
	expectedLength := netlinkErrorLen
	if code < 0 && flags&unix.NLM_F_CAPPED == 0 {
		expectedLength = 4 + align4(int(expected.length))
	}
	if len(payload) != expectedLength {
		return 0, fmt.Errorf("NETLINK_ROUTE error payload has invalid length %d", len(payload))
	}
	if expectedLength > netlinkErrorLen {
		requestLength := align4(int(expected.length))
		if requestLength > len(request) || !bytes.Equal(payload[4:], request[:requestLength]) {
			return 0, errors.New("NETLINK_ROUTE error does not contain the original request")
		}
	}
	return code, nil
}

func parseMessages(datagram []byte) ([]netlinkMessage, error) {
	var messages []netlinkMessage
	for len(datagram) > 0 {
		if len(datagram) < netlinkHeaderLen {
			return nil, errors.New("NETLINK_ROUTE reply has truncated header")
		}
		header, err := decodeHeader(datagram[:netlinkHeaderLen])
		if err != nil {
			return nil, err
		}
		if header.length < netlinkHeaderLen || header.length > maxMessageBytes || int(header.length) > len(datagram) {
			return nil, fmt.Errorf("NETLINK_ROUTE reply has invalid message length %d", header.length)
		}
		aligned := align4(int(header.length))
		if aligned > len(datagram) {
			return nil, errors.New("NETLINK_ROUTE reply has truncated message padding")
		}
		for _, value := range datagram[header.length:aligned] {
			if value != 0 {
				return nil, errors.New("NETLINK_ROUTE reply has nonzero message padding")
			}
		}
		payload := append([]byte(nil), datagram[netlinkHeaderLen:header.length]...)
		messages = append(messages, netlinkMessage{header: header, payload: payload})
		datagram = datagram[aligned:]
	}
	return messages, nil
}

func decodeHeader(data []byte) (netlinkHeader, error) {
	if len(data) < netlinkHeaderLen {
		return netlinkHeader{}, errors.New("NETLINK_ROUTE header is truncated")
	}
	return netlinkHeader{
		length:   binary.NativeEndian.Uint32(data[0:4]),
		typeCode: binary.NativeEndian.Uint16(data[4:6]),
		flags:    binary.NativeEndian.Uint16(data[6:8]),
		sequence: binary.NativeEndian.Uint32(data[8:12]),
		portID:   binary.NativeEndian.Uint32(data[12:16]),
	}, nil
}

func addressMatchesInterface(payload []byte, index int) (bool, error) {
	if len(payload) < ifAddrMessageLen {
		return false, errors.New("NETLINK_ROUTE address message is truncated")
	}
	if payload[0] != unix.AF_INET || payload[1] > 32 {
		return false, errors.New("NETLINK_ROUTE address message has invalid IPv4 header")
	}
	attributes, err := parseAttributes(payload[ifAddrMessageLen:])
	if err != nil {
		return false, err
	}
	for _, attribute := range attributes {
		if (attribute.typeCode == unix.IFA_ADDRESS || attribute.typeCode == unix.IFA_LOCAL) && len(attribute.value) != 4 {
			return false, errors.New("NETLINK_ROUTE address has malformed IPv4 attribute")
		}
	}
	return binary.NativeEndian.Uint32(payload[4:8]) == uint32(index), nil
}

func routeMatchesInterface(payload []byte, index int) (bool, error) {
	if len(payload) < routeMessageLen {
		return false, errors.New("NETLINK_ROUTE route message is truncated")
	}
	if payload[0] != unix.AF_INET || payload[1] > 32 || payload[2] > 32 {
		return false, errors.New("NETLINK_ROUTE route message has invalid IPv4 header")
	}
	attributes, err := parseAttributes(payload[routeMessageLen:])
	if err != nil {
		return false, err
	}
	table := uint32(payload[4])
	var outputInterface uint32
	seenTable := false
	seenOutputInterface := false
	for _, attribute := range attributes {
		switch attribute.typeCode {
		case unix.RTA_TABLE:
			if seenTable || len(attribute.value) != 4 {
				return false, errors.New("NETLINK_ROUTE route has malformed table attribute")
			}
			seenTable = true
			table = binary.NativeEndian.Uint32(attribute.value)
		case unix.RTA_OIF:
			if seenOutputInterface || len(attribute.value) != 4 {
				return false, errors.New("NETLINK_ROUTE route has malformed output-interface attribute")
			}
			seenOutputInterface = true
			outputInterface = binary.NativeEndian.Uint32(attribute.value)
		}
	}
	return table == unix.RT_TABLE_MAIN && seenOutputInterface && outputInterface == uint32(index), nil
}

func parseAttributes(data []byte) ([]routeAttribute, error) {
	var attributes []routeAttribute
	for len(data) > 0 {
		if len(data) < routeAttrLen {
			return nil, errors.New("NETLINK_ROUTE attribute header is truncated")
		}
		length := int(binary.NativeEndian.Uint16(data[0:2]))
		if length < routeAttrLen || length > len(data) {
			return nil, fmt.Errorf("NETLINK_ROUTE attribute has invalid length %d", length)
		}
		aligned := align4(length)
		if aligned > len(data) {
			return nil, errors.New("NETLINK_ROUTE attribute padding is truncated")
		}
		for _, value := range data[length:aligned] {
			if value != 0 {
				return nil, errors.New("NETLINK_ROUTE attribute has nonzero padding")
			}
		}
		attributes = append(attributes, routeAttribute{
			typeCode: binary.NativeEndian.Uint16(data[2:4]),
			value:    append([]byte(nil), data[routeAttrLen:length]...),
		})
		data = data[aligned:]
	}
	return attributes, nil
}

func align4(length int) int {
	return (length + 3) &^ 3
}
