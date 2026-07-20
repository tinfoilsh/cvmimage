package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	networkReadyTimeout      = 90 * time.Second
	networkReadyPollInterval = 500 * time.Millisecond

	etherTypeAll       = 0x0003
	etherTypeIPv4      = 0x0800
	ethernetHeaderLen  = 14
	ipv4HeaderLen      = 20
	udpHeaderLen       = 8
	ipv4ProtocolUDP    = 17
	ipv4DefaultTTL     = 64
	dhcpFrameBufferLen = 2048
)

func waitForNetworkReady(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, networkReadyTimeout)
	defer cancel()

	activated, err := activateExternalEthernetLinks(ctx, "/sys/class/net", runCommand)
	if err != nil {
		bootLogf("Warning: failed to activate guest Ethernet links: %v", err)
	} else if len(activated) > 0 {
		bootLogf("Activated guest Ethernet links: %s", strings.Join(activated, ", "))
	}

	bootLogf("Starting Tinfoil DHCPv4 configuration: %s", networkStateSummary())
	if detail, err := configureExternalEthernetDHCPv4(ctx, "/sys/class/net", runCommand); err != nil {
		bootLogf("Warning: DHCPv4 configuration failed: %v", err)
	} else if detail != "" {
		bootLogf("DHCPv4 configured: %s", detail)
	}

	var lastErr error
	for {
		detail, err := networkReady("/proc/net/route", "/etc/resolv.conf")
		if err == nil {
			return detail, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			summary := networkStateSummary()
			bootLogf("Network readiness timeout: %v; %s", lastErr, summary)
			return "", fmt.Errorf("network not ready before timeout: %w; %s", lastErr, summary)
		case <-time.After(networkReadyPollInterval):
		}
	}
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func activateExternalEthernetLinks(ctx context.Context, sysClassNet string, run commandRunner) ([]string, error) {
	links, err := externalEthernetLinks(sysClassNet)
	if err != nil {
		return nil, err
	}

	var activated []string
	for _, link := range links {
		output, err := run(ctx, "/usr/sbin/ip", "link", "set", "dev", link, "up")
		if err != nil {
			detail := strings.TrimSpace(string(output))
			if detail != "" {
				return activated, fmt.Errorf("ip link set dev %s up: %w: %s", link, err, detail)
			}
			return activated, fmt.Errorf("ip link set dev %s up: %w", link, err)
		}
		activated = append(activated, link)
	}
	return activated, nil
}

func externalEthernetLinks(sysClassNet string) ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", sysClassNet, err)
	}

	var links []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "e") {
			continue
		}
		state, err := os.ReadFile(filepath.Join(sysClassNet, name, "operstate"))
		if err == nil && strings.TrimSpace(string(state)) == "up" {
			continue
		}
		links = append(links, name)
	}
	sort.Strings(links)
	return links, nil
}

func kernelEthernetLinks(sysClassNet string) ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", sysClassNet, err)
	}

	var links []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "e") {
			links = append(links, name)
		}
	}
	sort.Strings(links)
	return links, nil
}

func configureExternalEthernetDHCPv4(ctx context.Context, sysClassNet string, run commandRunner) (string, error) {
	links, err := kernelEthernetLinks(sysClassNet)
	if err != nil {
		return "", err
	}
	if len(links) == 0 {
		return "", nil
	}

	var errs []string
	for _, link := range links {
		bootLogf("Requesting DHCPv4 lease on %s", link)
		lease, err := requestDHCPv4Lease(ctx, link)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", link, err))
			continue
		}
		if err := applyDHCPv4Lease(ctx, link, lease, run); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", link, err))
			continue
		}
		return fmt.Sprintf("%s address=%s/%d router=%s dns=%s", link, lease.IP, lease.PrefixLength, lease.Router, joinIPs(lease.DNS)), nil
	}
	return "", fmt.Errorf("%s", strings.Join(errs, "; "))
}

type dhcpv4Lease struct {
	IP           net.IP
	PrefixLength int
	Router       net.IP
	DNS          []net.IP
	ServerID     net.IP
}

const (
	dhcpClientPort = 68
	dhcpServerPort = 67
	dhcpMagic      = 0x63825363

	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5

	dhcpOptPad          = 0
	dhcpOptSubnetMask   = 1
	dhcpOptRouter       = 3
	dhcpOptDNS          = 6
	dhcpOptRequestedIP  = 50
	dhcpOptMessageType  = 53
	dhcpOptServerID     = 54
	dhcpOptParameterReq = 55
	dhcpOptClientID     = 61
	dhcpOptEnd          = 255
)

func requestDHCPv4Lease(ctx context.Context, ifname string) (*dhcpv4Lease, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("finding interface: %w", err)
	}
	if len(iface.HardwareAddr) < 6 {
		return nil, fmt.Errorf("interface has no Ethernet hardware address")
	}

	xid, err := randomXID()
	if err != nil {
		return nil, err
	}
	conn, err := listenRawDHCPv4(iface)
	if err != nil {
		return nil, err
	}
	defer conn.close()

	discover := buildDHCPv4Packet(dhcpDiscover, xid, iface.HardwareAddr, nil, nil)
	offer, err := exchangeRawDHCPv4(ctx, conn, discover, xid, iface.HardwareAddr, dhcpOffer)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	if offer.ServerID == nil {
		return nil, fmt.Errorf("offer missing server identifier")
	}

	request := buildDHCPv4Packet(dhcpRequest, xid, iface.HardwareAddr, offer.IP, offer.ServerID)
	ack, err := exchangeRawDHCPv4(ctx, conn, request, xid, iface.HardwareAddr, dhcpAck)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	return ack, nil
}

type rawDHCPv4Conn struct {
	fd      int
	ifindex int
	hw      net.HardwareAddr
}

func listenRawDHCPv4(iface *net.Interface) (*rawDHCPv4Conn, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherTypeAll)))
	if err != nil {
		return nil, fmt.Errorf("opening raw DHCP socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(etherTypeIPv4),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("binding raw DHCP socket to %s: %w", iface.Name, err)
	}
	return &rawDHCPv4Conn{fd: fd, ifindex: iface.Index, hw: append(net.HardwareAddr(nil), iface.HardwareAddr[:6]...)}, nil
}

func (conn *rawDHCPv4Conn) close() {
	_ = syscall.Close(conn.fd)
}

func exchangeRawDHCPv4(ctx context.Context, conn *rawDHCPv4Conn, request []byte, xid [4]byte, hw net.HardwareAddr, wantType byte) (*dhcpv4Lease, error) {
	deadline := time.Now().Add(20 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	var lastErr error
	for attempt := 0; attempt < 4 && time.Now().Before(deadline); attempt++ {
		if err := conn.send(request); err != nil {
			return nil, fmt.Errorf("sending DHCP packet: %w", err)
		}
		attemptDeadline := time.Now().Add(2 * time.Second)
		if deadline.Before(attemptDeadline) {
			attemptDeadline = deadline
		}
		for time.Now().Before(attemptDeadline) {
			payload, err := conn.recv(attemptDeadline)
			if err != nil {
				if errorsIsTimeout(err) {
					lastErr = err
					break
				}
				return nil, fmt.Errorf("reading DHCP packet: %w", err)
			}
			lease, msgType, err := parseDHCPv4Packet(payload, xid, hw)
			if err != nil {
				lastErr = err
				continue
			}
			if msgType == wantType {
				return lease, nil
			}
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("timed out")
}

func (conn *rawDHCPv4Conn) send(payload []byte) error {
	frame := buildEthernetIPv4UDPFrame(conn.hw, ethernetBroadcast(), net.IPv4zero, net.IPv4bcast, dhcpClientPort, dhcpServerPort, payload)
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(etherTypeIPv4),
		Ifindex:  conn.ifindex,
		Halen:    6,
	}
	copy(addr.Addr[:], ethernetBroadcast())
	return syscall.Sendto(conn.fd, frame, 0, addr)
}

func (conn *rawDHCPv4Conn) recv(deadline time.Time) ([]byte, error) {
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return nil, os.ErrDeadlineExceeded
	}
	if err := syscall.SetsockoptTimeval(conn.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, durationToTimeval(timeout)); err != nil {
		return nil, err
	}

	buf := make([]byte, dhcpFrameBufferLen)
	n, _, err := syscall.Recvfrom(conn.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return dhcpv4PayloadFromEthernetFrame(buf[:n])
}

func buildEthernetIPv4UDPFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	frame := make([]byte, ethernetHeaderLen+ipv4HeaderLen+udpHeaderLen+len(payload))
	copy(frame[0:6], dstMAC[:6])
	copy(frame[6:12], srcMAC[:6])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)

	ip := frame[ethernetHeaderLen : ethernetHeaderLen+ipv4HeaderLen]
	ip[0] = 0x45
	totalIPLength := ipv4HeaderLen + udpHeaderLen + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLength))
	ip[8] = ipv4DefaultTTL
	ip[9] = ipv4ProtocolUDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	udp := frame[ethernetHeaderLen+ipv4HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderLen+len(payload)))
	copy(udp[udpHeaderLen:], payload)
	return frame
}

func dhcpv4PayloadFromEthernetFrame(frame []byte) ([]byte, error) {
	if len(frame) < ethernetHeaderLen+ipv4HeaderLen+udpHeaderLen {
		return nil, fmt.Errorf("short Ethernet frame: %d bytes", len(frame))
	}
	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
		return nil, fmt.Errorf("non-IPv4 Ethernet frame")
	}

	ip := frame[ethernetHeaderLen:]
	if ip[0]>>4 != 4 {
		return nil, fmt.Errorf("non-IPv4 packet")
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(ip) < ihl+udpHeaderLen {
		return nil, fmt.Errorf("short IPv4 packet")
	}
	if ip[9] != ipv4ProtocolUDP {
		return nil, fmt.Errorf("non-UDP IPv4 packet")
	}
	totalLength := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLength == 0 || totalLength > len(ip) {
		totalLength = len(ip)
	}
	if totalLength < ihl+udpHeaderLen {
		return nil, fmt.Errorf("short IPv4 total length")
	}

	udp := ip[ihl:totalLength]
	srcPort := int(binary.BigEndian.Uint16(udp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(udp[2:4]))
	if srcPort != dhcpServerPort || dstPort != dhcpClientPort {
		return nil, fmt.Errorf("non-DHCP server reply")
	}
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < udpHeaderLen || udpLength > len(udp) {
		udpLength = len(udp)
	}
	return udp[udpHeaderLen:udpLength], nil
}

func buildDHCPv4Packet(messageType byte, xid [4]byte, hw net.HardwareAddr, requestedIP, serverID net.IP) []byte {
	packet := make([]byte, 240, 300)
	packet[0] = 1 // BOOTREQUEST
	packet[1] = 1 // Ethernet
	packet[2] = 6
	copy(packet[4:8], xid[:])
	packet[10] = 0x80 // Broadcast replies until the address is configured.
	copy(packet[28:34], hw[:6])
	binary.BigEndian.PutUint32(packet[236:240], dhcpMagic)

	packet = appendDHCPOption(packet, dhcpOptMessageType, []byte{messageType})
	packet = appendDHCPOption(packet, dhcpOptClientID, append([]byte{1}, hw[:6]...))
	if requestedIP := requestedIP.To4(); requestedIP != nil {
		packet = appendDHCPOption(packet, dhcpOptRequestedIP, requestedIP)
	}
	if serverID := serverID.To4(); serverID != nil {
		packet = appendDHCPOption(packet, dhcpOptServerID, serverID)
	}
	packet = appendDHCPOption(packet, dhcpOptParameterReq, []byte{dhcpOptSubnetMask, dhcpOptRouter, dhcpOptDNS, dhcpOptServerID})
	packet = append(packet, dhcpOptEnd)
	for len(packet) < 300 {
		packet = append(packet, 0)
	}
	return packet
}

func parseDHCPv4Packet(packet []byte, xid [4]byte, hw net.HardwareAddr) (*dhcpv4Lease, byte, error) {
	if len(packet) < 240 {
		return nil, 0, fmt.Errorf("short DHCP packet: %d bytes", len(packet))
	}
	if packet[0] != 2 {
		return nil, 0, fmt.Errorf("not a BOOTREPLY")
	}
	if string(packet[4:8]) != string(xid[:]) {
		return nil, 0, fmt.Errorf("mismatched transaction id")
	}
	if string(packet[28:34]) != string(hw[:6]) {
		return nil, 0, fmt.Errorf("mismatched hardware address")
	}
	if binary.BigEndian.Uint32(packet[236:240]) != dhcpMagic {
		return nil, 0, fmt.Errorf("missing DHCP magic cookie")
	}

	options := parseDHCPOptions(packet[240:])
	messageType := firstOptionByte(options[dhcpOptMessageType])
	lease := &dhcpv4Lease{
		IP:       copyIPv4(packet[16:20]),
		ServerID: optionIPv4(options[dhcpOptServerID]),
		Router:   firstOptionIPv4(options[dhcpOptRouter]),
		DNS:      optionIPv4List(options[dhcpOptDNS]),
	}
	mask := optionIPv4(options[dhcpOptSubnetMask])
	if mask != nil {
		if ones, bits := net.IPMask(mask).Size(); bits == 32 {
			lease.PrefixLength = ones
		}
	}
	if lease.PrefixLength == 0 {
		lease.PrefixLength = 24
	}
	if lease.IP == nil || lease.IP.Equal(net.IPv4zero) {
		return nil, 0, fmt.Errorf("DHCP packet missing yiaddr")
	}
	if lease.Router == nil {
		return nil, 0, fmt.Errorf("DHCP packet missing router option")
	}
	return lease, messageType, nil
}

func parseDHCPOptions(data []byte) map[byte][]byte {
	options := make(map[byte][]byte)
	for i := 0; i < len(data); {
		code := data[i]
		i++
		switch code {
		case dhcpOptPad:
			continue
		case dhcpOptEnd:
			return options
		}
		if i >= len(data) {
			return options
		}
		length := int(data[i])
		i++
		if i+length > len(data) {
			return options
		}
		options[code] = append([]byte(nil), data[i:i+length]...)
		i += length
	}
	return options
}

func applyDHCPv4Lease(ctx context.Context, ifname string, lease *dhcpv4Lease, run commandRunner) error {
	address := fmt.Sprintf("%s/%d", lease.IP, lease.PrefixLength)
	if output, err := run(ctx, "/usr/sbin/ip", "addr", "replace", address, "dev", ifname); err != nil {
		return fmt.Errorf("ip addr replace %s dev %s: %w: %s", address, ifname, err, strings.TrimSpace(string(output)))
	}
	if output, err := run(ctx, "/usr/sbin/ip", "route", "replace", "default", "via", lease.Router.String(), "dev", ifname); err != nil {
		return fmt.Errorf("ip route replace default via %s dev %s: %w: %s", lease.Router, ifname, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func appendDHCPOption(packet []byte, code byte, value []byte) []byte {
	packet = append(packet, code, byte(len(value)))
	return append(packet, value...)
}

func randomXID() ([4]byte, error) {
	var xid [4]byte
	if _, err := rand.Read(xid[:]); err != nil {
		return xid, fmt.Errorf("generating DHCP transaction id: %w", err)
	}
	return xid, nil
}

func ethernetBroadcast() net.HardwareAddr {
	return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}

func durationToTimeval(duration time.Duration) *syscall.Timeval {
	if duration < time.Millisecond {
		duration = time.Millisecond
	}
	return &syscall.Timeval{
		Sec:  int64(duration / time.Second),
		Usec: int64((duration % time.Second) / time.Microsecond),
	}
}

func errorsIsTimeout(err error) bool {
	return err == os.ErrDeadlineExceeded || err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}

func ipv4Checksum(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func copyIPv4(data []byte) net.IP {
	if len(data) < net.IPv4len {
		return nil
	}
	ip := net.IPv4(data[0], data[1], data[2], data[3])
	return ip.To4()
}

func optionIPv4(data []byte) net.IP {
	if len(data) < net.IPv4len {
		return nil
	}
	return copyIPv4(data[:net.IPv4len])
}

func firstOptionIPv4(data []byte) net.IP {
	return optionIPv4(data)
}

func optionIPv4List(data []byte) []net.IP {
	var out []net.IP
	for len(data) >= net.IPv4len {
		out = append(out, copyIPv4(data[:net.IPv4len]))
		data = data[net.IPv4len:]
	}
	return out
}

func firstOptionByte(data []byte) byte {
	if len(data) == 0 {
		return 0
	}
	return data[0]
}

func joinIPs(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}

func networkReady(routePath, resolvPath string) (string, error) {
	ok, err := hasDefaultIPv4Route(routePath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no default IPv4 route")
	}
	if err := resolvConfReady(resolvPath); err != nil {
		return "", err
	}
	return "default IPv4 route and resolver config ready", nil
}

func hasDefaultIPv4Route(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	if !scanner.Scan() {
		return false, fmt.Errorf("%s is empty", path)
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		const (
			routeDestination = 1
			routeFlags       = 3
			rtfUp            = 0x1
		)
		if fields[routeDestination] != "00000000" {
			continue
		}
		flags, err := strconv.ParseInt(fields[routeFlags], 16, 64)
		if err != nil {
			continue
		}
		if flags&rtfUp != 0 {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scanning %s: %w", path, err)
	}
	return false, nil
}

func resolvConfReady(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning %s: %w", path, err)
	}
	return fmt.Errorf("%s has no nameserver entry", path)
}

func networkStateSummary() string {
	var parts []string
	if entries, err := os.ReadDir("/sys/class/net"); err == nil {
		var interfaces []string
		for _, entry := range entries {
			name := entry.Name()
			interfaces = append(interfaces, name+interfaceState(name))
		}
		parts = append(parts, "interfaces="+strings.Join(interfaces, ","))
	} else {
		parts = append(parts, fmt.Sprintf("interfaces=<error:%v>", err))
	}

	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		var rows []string
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				rows = append(rows, line)
			}
		}
		parts = append(parts, "routes="+strings.Join(rows, "|"))
	} else {
		parts = append(parts, fmt.Sprintf("routes=<error:%v>", err))
	}

	return strings.Join(parts, "; ")
}

func interfaceState(name string) string {
	var fields []string
	for _, file := range []string{"operstate", "carrier", "address"} {
		data, err := os.ReadFile("/sys/class/net/" + name + "/" + file)
		if err == nil {
			fields = append(fields, file+"="+strings.TrimSpace(string(data)))
		}
	}
	if len(fields) == 0 {
		return ""
	}
	return "(" + strings.Join(fields, ",") + ")"
}
