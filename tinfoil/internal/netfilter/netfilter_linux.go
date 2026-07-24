package netfilter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tableName                = "tinfoil"
	maxNetworks              = 33
	maxPorts                 = 64
	maxSetElements           = 1000
	maxTotalSetElements      = 8000
	maxOperations            = 1024
	maxOperationBytes        = 16 << 10
	maxTransactionBytes      = 512 << 10
	maxDatagramBytes         = 64 << 10
	transactionTimeout       = 5 * time.Second
	cancellationPollInterval = 50 * time.Millisecond
	netlinkHeaderLen         = unix.NLMSG_HDRLEN
	nfgenMessageLen          = 4
	netlinkAttributeLen      = 4
	netlinkErrorCodeLen      = 4
	cappedAckPayloadLen      = netlinkErrorCodeLen + netlinkHeaderLen
	nfTablesSubsystemType    = unix.NFNL_SUBSYS_NFTABLES << 8
	nfDrop                   = 0
	nfAccept                 = 1
	ctStateEstablished       = 1
	ctStateRelated           = 2
	ctStateNew               = 3
	ctStatusDNAT             = 1 << 5
)

type Egress uint8

const (
	EgressClosed Egress = iota
	EgressOpen
	EgressAllowlist
)

type Network struct {
	Name   string
	Egress Egress
}

type operation struct {
	typeCode uint16
	flags    uint16
	payload  []byte
}

type expectedAck struct {
	length   uint32
	typeCode uint16
	flags    uint16
	sequence uint32
	portID   uint32
}

type expression [][]byte

var nextSequence atomic.Uint32

var blockedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32"),
}

var blockedIPv6 = []netip.Prefix{
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("::1/128"),
}

func Initialize(ctx context.Context) error {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("find loopback interface: %w", err)
	}
	operations := []operation{
		message(unix.NFT_MSG_DELTABLE, unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE, 0, nil),
		message(unix.NFT_MSG_NEWTABLE, createFlags(), unix.NFPROTO_INET,
			attribute(unix.NFTA_TABLE_NAME, cstring(tableName))),
		newChain("http01", nil),
		baseChain("input", unix.NF_INET_LOCAL_IN, nfDrop),
		baseChain("forward", unix.NF_INET_FORWARD, nfDrop),
		baseChain("output", unix.NF_INET_LOCAL_OUT, nfAccept),
	}
	operations = append(operations,
		appendRule("input", true, interfaceIndex(unix.NFT_META_IIF, loopback.Index), verdict(nfAccept)),
		appendRule("input", true, conntrackStates((1<<ctStateEstablished)|(1<<ctStateRelated)), verdict(nfAccept)),
		appendRule("input", true, verdictJump("http01")),
		appendRule("input", true, networkProtocol(unix.NFPROTO_IPV4), payloadByte(unix.NFT_PAYLOAD_NETWORK_HEADER, 9, 1), compare([]byte{unix.IPPROTO_ICMP}, unix.NFT_CMP_EQ), verdict(nfAccept)),
		appendRule("input", true, networkProtocol(unix.NFPROTO_IPV6), metaByte(unix.NFT_META_L4PROTO), compare([]byte{unix.IPPROTO_ICMPV6}, unix.NFT_CMP_EQ), verdict(nfAccept)),
		appendRule("input", true, tcpDestinationPort(443), verdict(nfAccept)),
	)
	return transact(ctx, operations)
}

func InstallNetworks(ctx context.Context, networks []Network, debugForward bool) error {
	if len(networks) > maxNetworks {
		return fmt.Errorf("network count %d exceeds %d", len(networks), maxNetworks)
	}
	ordered := append([]Network(nil), networks...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	operations := make([]operation, 0, len(ordered)*8)
	previous := ""
	for _, network := range ordered {
		if err := validateNetwork(network, previous); err != nil {
			return err
		}
		previous = network.Name
		if network.Egress > EgressAllowlist {
			return fmt.Errorf("network %q has invalid egress mode %d", network.Name, network.Egress)
		}
	}
	for networkIndex, network := range ordered {
		device, err := net.InterfaceByName(network.Name)
		if err != nil {
			return fmt.Errorf("find network interface %q: %w", network.Name, err)
		}
		index := device.Index
		operations = append(operations,
			appendRule("forward", true, interfaceIndex(unix.NFT_META_IIF, index), interfaceIndex(unix.NFT_META_OIF, index), verdict(nfAccept)),
			appendRule("forward", true, interfaceIndex(unix.NFT_META_OIF, index), conntrackStates((1<<ctStateEstablished)|(1<<ctStateRelated)), verdict(nfAccept)),
			appendRule("input", false, interfaceIndex(unix.NFT_META_IIF, index), conntrackStates(1<<ctStateNew), verdict(nfDrop)),
		)
		switch network.Egress {
		case EgressClosed:
		case EgressOpen:
			ipv4Rule, err := publicDestinationRule(index, unix.NFPROTO_IPV4, blockedIPv4)
			if err != nil {
				return err
			}
			ipv6Rule, err := publicDestinationRule(index, unix.NFPROTO_IPV6, blockedIPv6)
			if err != nil {
				return err
			}
			operations = append(operations,
				ipv4Rule,
				ipv6Rule,
			)
		case EgressAllowlist:
			setName := "allow-" + network.Name
			setID := uint32(networkIndex + 1)
			operations = append(operations, newIPv4Set(setName, setID))
			for _, prefix := range blockedIPv4 {
				operations = append(operations, prefixRule(index, prefix, nfDrop))
			}
			for _, prefix := range blockedIPv6 {
				operations = append(operations, prefixRule(index, prefix, nfDrop))
			}
			operations = append(operations, appendRule("forward", true,
				interfaceIndex(unix.NFT_META_IIF, index), networkProtocol(unix.NFPROTO_IPV4),
				payloadAddress(unix.NFPROTO_IPV4, 1), lookup(setName, setID, 1), verdict(nfAccept)))
		}
	}
	if debugForward {
		dockerBridge, err := net.InterfaceByName("docker0")
		if err != nil {
			return fmt.Errorf("find debug bridge interface: %w", err)
		}
		operations = append(operations,
			appendRule("forward", true, interfaceIndex(unix.NFT_META_OIF, dockerBridge.Index), conntrackStatus(ctStatusDNAT), tcpDestinationPort(2222), verdict(nfAccept)),
			appendRule("forward", true, interfaceIndex(unix.NFT_META_IIF, dockerBridge.Index), conntrackStates((1<<ctStateEstablished)|(1<<ctStateRelated)), verdict(nfAccept)),
		)
	}
	return transact(ctx, operations)
}

func OpenInboundPorts(ctx context.Context, ports []uint16) error {
	if len(ports) > maxPorts {
		return fmt.Errorf("inbound port count %d exceeds %d", len(ports), maxPorts)
	}
	operations := make([]operation, 0, len(ports))
	for _, port := range ports {
		if port == 0 {
			return errors.New("inbound port must be nonzero")
		}
		operations = append(operations, appendRule("input", true, tcpDestinationPort(port), verdict(nfAccept)))
	}
	return transact(ctx, operations)
}

func OpenHTTP01(ctx context.Context) error {
	return transact(ctx, []operation{appendRule("http01", true, tcpDestinationPort(80), verdict(nfAccept))})
}

func CloseHTTP01(ctx context.Context) error {
	return transact(ctx, []operation{flushChain("http01")})
}

func ReplaceAllowSets(ctx context.Context, sets map[string][]netip.Addr) error {
	if len(sets) > maxNetworks {
		return fmt.Errorf("allow-set count %d exceeds %d", len(sets), maxNetworks)
	}
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	operations := make([]operation, 0, len(names)*2)
	total := 0
	for _, name := range names {
		if err := validateSetName(name); err != nil {
			return err
		}
		addresses := sets[name]
		if len(addresses) > maxSetElements {
			return fmt.Errorf("allow set %q has %d elements; maximum is %d", name, len(addresses), maxSetElements)
		}
		total += len(addresses)
		if total > maxTotalSetElements {
			return fmt.Errorf("allow sets contain more than %d total elements", maxTotalSetElements)
		}
		values := make([][4]byte, len(addresses))
		for index, address := range addresses {
			if !address.Is4() {
				return fmt.Errorf("allow set %q element %d is not IPv4", name, index)
			}
			values[index] = address.As4()
			if index > 0 && bytes.Compare(values[index-1][:], values[index][:]) >= 0 {
				return fmt.Errorf("allow set %q elements are not strictly sorted", name)
			}
		}
		operations = append(operations, flushSet(name))
		if len(values) > 0 {
			operations = append(operations, addSetElements(name, values))
		}
	}
	return transact(ctx, operations)
}

func validateNetwork(network Network, previous string) error {
	if network.Name <= previous {
		return fmt.Errorf("network names are duplicated or unsorted after ordering: %q", network.Name)
	}
	if len(network.Name) == 0 || len(network.Name) > unix.IFNAMSIZ-1 {
		return fmt.Errorf("invalid network name length %d", len(network.Name))
	}
	for index, character := range []byte(network.Name) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' && index > 0 && index < len(network.Name)-1 {
			continue
		}
		return fmt.Errorf("invalid network name %q", network.Name)
	}
	return nil
}

func validateSetName(name string) error {
	if len(name) <= len("allow-") || len(name) > len("allow-")+unix.IFNAMSIZ-1 || name[:len("allow-")] != "allow-" {
		return fmt.Errorf("invalid allow-set name %q", name)
	}
	return validateNetwork(Network{Name: name[len("allow-"):]}, "")
}

func transact(ctx context.Context, operations []operation) error {
	if len(operations) == 0 {
		return nil
	}
	if len(operations) > maxOperations {
		return fmt.Errorf("netfilter transaction has %d operations; maximum is %d", len(operations), maxOperations)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("open NETLINK_NETFILTER socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_CAP_ACK, 1); err != nil {
		return fmt.Errorf("enable capped netlink acknowledgements: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, maxTransactionBytes); err != nil {
		return fmt.Errorf("bound NETLINK_NETFILTER send buffer: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, maxTransactionBytes); err != nil {
		return fmt.Errorf("bound NETLINK_NETFILTER receive buffer: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind NETLINK_NETFILTER socket: %w", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("read NETLINK_NETFILTER port ID: %w", err)
	}
	portID := address.(*unix.SockaddrNetlink).Pid
	sequence := newSequence()
	requests, expected, err := encodeTransaction(operations, sequence, portID)
	if err != nil {
		return err
	}
	request := make([]byte, 0, maxTransactionBytes)
	for _, message := range requests {
		request = append(request, message...)
	}
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send NETLINK_NETFILTER transaction: %w", err)
	}
	deadline := time.Now().Add(transactionTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	buffer := make([]byte, maxDatagramBytes)
	for len(expected) > 0 {
		if err := waitReadable(ctx, fd, deadline); err != nil {
			return err
		}
		count, source, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return fmt.Errorf("receive NETLINK_NETFILTER acknowledgement: %w", err)
		}
		netlinkSource, ok := source.(*unix.SockaddrNetlink)
		if !ok || netlinkSource.Pid != 0 {
			return errors.New("NETLINK_NETFILTER acknowledgement has non-kernel sender")
		}
		if err := consumeAcknowledgements(buffer[:count], portID, expected); err != nil {
			return err
		}
	}
	return nil
}

func waitReadable(ctx context.Context, fd int, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("NETLINK_NETFILTER transaction canceled: %w", err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("NETLINK_NETFILTER transaction timed out")
		}
		pollDuration := min(remaining, cancellationPollInterval)
		milliseconds := int(pollDuration / time.Millisecond)
		if milliseconds < 1 {
			milliseconds = 1
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, milliseconds)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll NETLINK_NETFILTER socket: %w", err)
		}
		if ready > 0 {
			return nil
		}
	}
}

func newSequence() uint32 {
	return nextSequence.Add(1)
}

func encodeTransaction(operations []operation, sequence, portID uint32) ([][]byte, map[uint32]expectedAck, error) {
	requests := make([][]byte, 0, len(operations)+2)
	requests = append(requests, encodeMessage(unix.NFNL_MSG_BATCH_BEGIN, unix.NLM_F_REQUEST, sequence, portID, nfgen(unix.NFPROTO_UNSPEC, unix.NFNL_SUBSYS_NFTABLES)))
	expected := make(map[uint32]expectedAck, len(operations))
	totalBytes := len(requests[0])
	for index, operation := range operations {
		if len(operation.payload)+netlinkHeaderLen > maxOperationBytes {
			return nil, nil, fmt.Errorf("netfilter operation %d exceeds %d bytes", index, maxOperationBytes)
		}
		operationSequence := sequence + uint32(index) + 1
		expected[operationSequence] = expectedAck{
			length: uint32(netlinkHeaderLen + len(operation.payload)), typeCode: operation.typeCode,
			flags: operation.flags, sequence: operationSequence, portID: portID,
		}
		request := encodeMessage(operation.typeCode, operation.flags, operationSequence, portID, operation.payload)
		requests = append(requests, request)
		totalBytes += len(request)
	}
	end := encodeMessage(unix.NFNL_MSG_BATCH_END, unix.NLM_F_REQUEST, sequence+uint32(len(operations))+1, portID, nfgen(unix.NFPROTO_UNSPEC, unix.NFNL_SUBSYS_NFTABLES))
	requests = append(requests, end)
	totalBytes += len(end)
	if totalBytes > maxTransactionBytes {
		return nil, nil, fmt.Errorf("netfilter transaction exceeds %d bytes", maxTransactionBytes)
	}
	return requests, expected, nil
}

func consumeAcknowledgements(datagram []byte, portID uint32, expected map[uint32]expectedAck) error {
	for len(datagram) > 0 {
		if len(datagram) < netlinkHeaderLen {
			return errors.New("truncated NETLINK_NETFILTER acknowledgement header")
		}
		length := int(binary.NativeEndian.Uint32(datagram[0:4]))
		if length < netlinkHeaderLen || length > len(datagram) {
			return errors.New("invalid NETLINK_NETFILTER acknowledgement length")
		}
		typeCode := binary.NativeEndian.Uint16(datagram[4:6])
		flags := binary.NativeEndian.Uint16(datagram[6:8])
		sequence := binary.NativeEndian.Uint32(datagram[8:12])
		replyPortID := binary.NativeEndian.Uint32(datagram[12:16])
		if typeCode != unix.NLMSG_ERROR || flags != unix.NLM_F_CAPPED || replyPortID != portID {
			return fmt.Errorf("unexpected NETLINK_NETFILTER acknowledgement header type=%d flags=%#x port=%d", typeCode, flags, replyPortID)
		}
		request, ok := expected[sequence]
		if !ok {
			return fmt.Errorf("unexpected NETLINK_NETFILTER acknowledgement sequence %d", sequence)
		}
		if length != netlinkHeaderLen+cappedAckPayloadLen {
			return fmt.Errorf("NETLINK_NETFILTER acknowledgement payload length is %d", length-netlinkHeaderLen)
		}
		code := int32(binary.NativeEndian.Uint32(datagram[netlinkHeaderLen:length]))
		if code > 0 {
			return errors.New("NETLINK_NETFILTER acknowledgement has positive error code")
		}
		if code < 0 {
			return fmt.Errorf("NETLINK_NETFILTER operation type=%d sequence=%d failed: %w", request.typeCode, sequence, unix.Errno(-code))
		}
		embedded := datagram[netlinkHeaderLen+netlinkErrorCodeLen : length]
		if binary.NativeEndian.Uint32(embedded[0:4]) != request.length ||
			binary.NativeEndian.Uint16(embedded[4:6]) != request.typeCode ||
			binary.NativeEndian.Uint16(embedded[6:8]) != request.flags ||
			binary.NativeEndian.Uint32(embedded[8:12]) != request.sequence ||
			binary.NativeEndian.Uint32(embedded[12:16]) != request.portID {
			return errors.New("NETLINK_NETFILTER acknowledgement does not match request header")
		}
		delete(expected, sequence)
		aligned := align4(length)
		if aligned > len(datagram) {
			return errors.New("truncated NETLINK_NETFILTER acknowledgement padding")
		}
		for _, value := range datagram[length:aligned] {
			if value != 0 {
				return errors.New("nonzero NETLINK_NETFILTER acknowledgement padding")
			}
		}
		datagram = datagram[aligned:]
	}
	return nil
}

func encodeMessage(typeCode, flags uint16, sequence, portID uint32, payload []byte) []byte {
	length := netlinkHeaderLen + len(payload)
	message := make([]byte, align4(length))
	binary.NativeEndian.PutUint32(message[0:4], uint32(length))
	binary.NativeEndian.PutUint16(message[4:6], typeCode)
	binary.NativeEndian.PutUint16(message[6:8], flags)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	binary.NativeEndian.PutUint32(message[12:16], portID)
	copy(message[netlinkHeaderLen:], payload)
	return message
}

func message(kind, flags uint16, family byte, attrs []byte) operation {
	return operation{typeCode: nfTablesSubsystemType | kind, flags: flags, payload: append(nfgen(family, 0), attrs...)}
}

func createFlags() uint16 { return unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE }

func nfgen(family byte, resource uint16) []byte {
	value := make([]byte, nfgenMessageLen)
	value[0] = family
	binary.BigEndian.PutUint16(value[2:4], resource)
	return value
}

func attribute(typeCode uint16, value []byte) []byte {
	length := netlinkAttributeLen + len(value)
	result := make([]byte, align4(length))
	binary.NativeEndian.PutUint16(result[0:2], uint16(length))
	binary.NativeEndian.PutUint16(result[2:4], typeCode)
	copy(result[netlinkAttributeLen:], value)
	return result
}

func nested(typeCode uint16, value []byte) []byte {
	return attribute(unix.NLA_F_NESTED|typeCode, value)
}
func cstring(value string) []byte { return append([]byte(value), 0) }
func be32(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}
func native32(value uint32) []byte {
	result := make([]byte, 4)
	binary.NativeEndian.PutUint32(result, value)
	return result
}
func align4(value int) int { return (value + 3) &^ 3 }
