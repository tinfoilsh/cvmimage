package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExternalEthernetLinksSelectsDownKernelEthernetNames(t *testing.T) {
	dir := t.TempDir()
	for name, state := range map[string]string{
		"docker0": "down",
		"enp0s2":  "up",
		"ens5":    "down",
		"eth0":    "unknown",
		"lo":      "unknown",
		"veth0":   "down",
	} {
		linkDir := filepath.Join(dir, name)
		if err := os.Mkdir(linkDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(linkDir, "operstate"), []byte(state+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	links, err := externalEthernetLinks(dir)
	if err != nil {
		t.Fatalf("externalEthernetLinks() failed: %v", err)
	}
	want := []string{"ens5", "eth0"}
	if !reflect.DeepEqual(links, want) {
		t.Fatalf("externalEthernetLinks() = %v, want %v", links, want)
	}
}

func TestActivateExternalEthernetLinksUsesIPLinkSet(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"eth0", "ens5"} {
		linkDir := filepath.Join(dir, name)
		if err := os.Mkdir(linkDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(linkDir, "operstate"), []byte("down\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}

	activated, err := activateExternalEthernetLinks(context.Background(), dir, run)
	if err != nil {
		t.Fatalf("activateExternalEthernetLinks() failed: %v", err)
	}
	wantActivated := []string{"ens5", "eth0"}
	if !reflect.DeepEqual(activated, wantActivated) {
		t.Fatalf("activateExternalEthernetLinks() activated %v, want %v", activated, wantActivated)
	}
	wantCalls := []string{
		"/usr/sbin/ip link set dev ens5 up",
		"/usr/sbin/ip link set dev eth0 up",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("activateExternalEthernetLinks() calls %v, want %v", calls, wantCalls)
	}
}

func TestParseDHCPv4Ack(t *testing.T) {
	xid := [4]byte{1, 2, 3, 4}
	hw := net.HardwareAddr{0x52, 0x54, 0x00, 0xfb, 0xde, 0x43}
	packet := testDHCPv4Reply(t, xid, hw, net.IPv4(100, 64, 0, 98),
		[]byte{dhcpOptMessageType, 1, dhcpAck},
		[]byte{dhcpOptServerID, 4, 100, 64, 0, 1},
		[]byte{dhcpOptSubnetMask, 4, 255, 255, 240, 0},
		[]byte{dhcpOptRouter, 4, 100, 64, 0, 1},
		[]byte{dhcpOptDNS, 8, 1, 1, 1, 1, 9, 9, 9, 9},
	)

	lease, msgType, err := parseDHCPv4Packet(packet, xid, hw)
	if err != nil {
		t.Fatalf("parseDHCPv4Packet() failed: %v", err)
	}
	if msgType != dhcpAck {
		t.Fatalf("message type = %d, want %d", msgType, dhcpAck)
	}
	if !lease.IP.Equal(net.IPv4(100, 64, 0, 98)) {
		t.Fatalf("lease IP = %s", lease.IP)
	}
	if lease.PrefixLength != 20 {
		t.Fatalf("prefix length = %d, want 20", lease.PrefixLength)
	}
	if !lease.Router.Equal(net.IPv4(100, 64, 0, 1)) {
		t.Fatalf("router = %s", lease.Router)
	}
	if got := joinIPs(lease.DNS); got != "1.1.1.1,9.9.9.9" {
		t.Fatalf("DNS = %q", got)
	}
}

func TestDHCPv4PayloadFromEthernetFrame(t *testing.T) {
	xid := [4]byte{1, 2, 3, 4}
	hw := net.HardwareAddr{0x52, 0x54, 0x00, 0xfb, 0xde, 0x43}
	payload := testDHCPv4Reply(t, xid, hw, net.IPv4(100, 64, 0, 98),
		[]byte{dhcpOptMessageType, 1, dhcpOffer},
		[]byte{dhcpOptServerID, 4, 100, 64, 0, 1},
		[]byte{dhcpOptRouter, 4, 100, 64, 0, 1},
	)
	frame := buildEthernetIPv4UDPFrame(
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		hw,
		net.IPv4(100, 64, 0, 1),
		net.IPv4bcast,
		dhcpServerPort,
		dhcpClientPort,
		payload,
	)

	got, err := dhcpv4PayloadFromEthernetFrame(frame)
	if err != nil {
		t.Fatalf("dhcpv4PayloadFromEthernetFrame() failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestApplyDHCPv4LeaseUsesIPCommands(t *testing.T) {
	lease := &dhcpv4Lease{
		IP:           net.IPv4(100, 64, 0, 98).To4(),
		PrefixLength: 20,
		Router:       net.IPv4(100, 64, 0, 1).To4(),
	}

	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	if err := applyDHCPv4Lease(context.Background(), "eth0", lease, run); err != nil {
		t.Fatalf("applyDHCPv4Lease() failed: %v", err)
	}
	want := []string{
		"/usr/sbin/ip addr replace 100.64.0.98/20 dev eth0",
		"/usr/sbin/ip route replace default via 100.64.0.1 dev eth0",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func testDHCPv4Reply(t *testing.T, xid [4]byte, hw net.HardwareAddr, yiaddr net.IP, options ...[]byte) []byte {
	t.Helper()
	packet := make([]byte, 240, 300)
	packet[0] = 2
	packet[1] = 1
	packet[2] = 6
	copy(packet[4:8], xid[:])
	copy(packet[16:20], yiaddr.To4())
	copy(packet[28:34], hw[:6])
	binary.BigEndian.PutUint32(packet[236:240], dhcpMagic)
	for _, option := range options {
		packet = append(packet, option...)
	}
	packet = append(packet, dhcpOptEnd)
	return packet
}

func TestNetworkReadyRequiresDefaultRouteAndResolver(t *testing.T) {
	dir := t.TempDir()
	routePath := filepath.Join(dir, "route")
	resolvPath := filepath.Join(dir, "resolv.conf")

	route := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0102A8C0 0003 0 0 100 00000000 0 0 0\n"
	if err := os.WriteFile(routePath, []byte(route), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvPath, []byte("nameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}

	detail, err := networkReady(routePath, resolvPath)
	if err != nil {
		t.Fatalf("networkReady() failed: %v", err)
	}
	if detail == "" {
		t.Fatal("networkReady() returned empty detail")
	}
}

func TestNetworkReadyRejectsMissingDefaultRoute(t *testing.T) {
	dir := t.TempDir()
	routePath := filepath.Join(dir, "route")
	resolvPath := filepath.Join(dir, "resolv.conf")

	route := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 0002A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0\n"
	if err := os.WriteFile(routePath, []byte(route), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvPath, []byte("nameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := networkReady(routePath, resolvPath); err == nil {
		t.Fatal("networkReady() succeeded without a default route")
	}
}

func TestNetworkReadyRejectsMissingNameserver(t *testing.T) {
	dir := t.TempDir()
	routePath := filepath.Join(dir, "route")
	resolvPath := filepath.Join(dir, "resolv.conf")

	route := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0102A8C0 0003 0 0 100 00000000 0 0 0\n"
	if err := os.WriteFile(routePath, []byte(route), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvPath, []byte("# empty\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := networkReady(routePath, resolvPath); err == nil {
		t.Fatal("networkReady() succeeded without a nameserver")
	}
}
