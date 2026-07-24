package netfilter

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelContract(t *testing.T) {
	if os.Getenv("TINFOIL_NETFILTER_NETNS_TEST") != "1" {
		t.Skip("set TINFOIL_NETFILTER_NETNS_TEST=1 inside an isolated network namespace")
	}
	ctx := context.Background()
	if err := Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	invalidSet := message(unix.NFT_MSG_NEWSET, createFlags(), unix.NFPROTO_INET, nil)
	if err := transact(ctx, []operation{newIPv4Set("atomic-test", 100), invalidSet}); err == nil {
		t.Fatal("transaction containing malformed operation succeeded")
	}
	if err := transact(ctx, []operation{newIPv4Set("atomic-test", 101)}); err != nil {
		t.Fatalf("failed transaction committed its valid prefix: %v", err)
	}
	if err := InstallNetworks(ctx, []Network{
		{Name: "allow-net", Egress: EgressAllowlist},
		{Name: "closed-net", Egress: EgressClosed},
		{Name: "open-net", Egress: EgressOpen},
	}, false); err != nil {
		t.Fatalf("InstallNetworks: %v", err)
	}
	if err := OpenInboundPorts(ctx, []uint16{8443, 9443}); err != nil {
		t.Fatalf("OpenInboundPorts: %v", err)
	}
	if err := ReplaceAllowSets(ctx, map[string][]netip.Addr{
		"allow-allow-net": {netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("8.8.8.8")},
	}); err != nil {
		t.Fatalf("ReplaceAllowSets: %v", err)
	}
	if err := OpenHTTP01(ctx); err != nil {
		t.Fatalf("OpenHTTP01: %v", err)
	}
	if err := CloseHTTP01(ctx); err != nil {
		t.Fatalf("CloseHTTP01: %v", err)
	}
}

func TestKernelWorstCaseNetworkTransaction(t *testing.T) {
	if os.Getenv("TINFOIL_NETFILTER_WORST_CASE_TEST") != "1" {
		t.Skip("set TINFOIL_NETFILTER_WORST_CASE_TEST=1 inside an isolated network namespace with n00..n32")
	}
	ctx := context.Background()
	if err := Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	networks := make([]Network, maxNetworks)
	sets := make(map[string][]netip.Addr, maxNetworks)
	for index := range networks {
		name := fmt.Sprintf("n%02d", index)
		networks[index] = Network{Name: name, Egress: EgressAllowlist}
		sets["allow-"+name] = []netip.Addr{netip.AddrFrom4([4]byte{8, 8, byte(index), 1})}
	}
	if err := InstallNetworks(ctx, networks, false); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceAllowSets(ctx, sets); err != nil {
		t.Fatal(err)
	}
}

func TestKernelDebugForwardContract(t *testing.T) {
	if os.Getenv("TINFOIL_NETFILTER_DEBUG_TEST") != "1" {
		t.Skip("set TINFOIL_NETFILTER_DEBUG_TEST=1 inside an isolated network namespace with docker0 and debug-net")
	}
	ctx := context.Background()
	if err := Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := InstallNetworks(ctx, []Network{{Name: "debug-net", Egress: EgressClosed}}, true); err != nil {
		t.Fatal(err)
	}
}

func TestInstallNetworksRejectsInvalidContract(t *testing.T) {
	tests := []struct {
		name     string
		networks []Network
		want     string
	}{
		{name: "name", networks: []Network{{Name: "UPPER", Egress: EgressClosed}}, want: "invalid network name"},
		{name: "mode", networks: []Network{{Name: "lo", Egress: 99}}, want: "invalid egress mode"},
		{name: "duplicate", networks: []Network{{Name: "valid"}, {Name: "valid"}}, want: "duplicated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := InstallNetworks(context.Background(), test.networks, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestPublicDestinationRuleRejectsMixedFamilies(t *testing.T) {
	tests := []struct {
		name    string
		family  byte
		blocked []netip.Prefix
	}{
		{name: "IPv4 with IPv6 prefix", family: unix.NFPROTO_IPV4, blocked: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}},
		{name: "IPv6 with IPv4 prefix", family: unix.NFPROTO_IPV6, blocked: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		{name: "unsupported family", family: unix.NFPROTO_INET, blocked: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := publicDestinationRule(1, test.family, test.blocked); err == nil {
				t.Fatal("publicDestinationRule accepted invalid family contract")
			}
		})
	}
}

func TestWaitReadableObservesCancellationPromptly(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	started := time.Now()
	err = waitReadable(ctx, int(read.Fd()), time.Now().Add(transactionTimeout))
	if !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("waitReadable error = %v, want cancellation", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("waitReadable observed cancellation after %v", elapsed)
	}
}

func TestNewSequenceWrapsWithoutSharedReset(t *testing.T) {
	original := nextSequence.Load()
	t.Cleanup(func() { nextSequence.Store(original) })
	nextSequence.Store(^uint32(0) - 1)
	if got := newSequence(); got != ^uint32(0) {
		t.Fatalf("first sequence = %d", got)
	}
	if got := newSequence(); got != 0 {
		t.Fatalf("wrapped sequence = %d", got)
	}
	if got := newSequence(); got != 1 {
		t.Fatalf("post-wrap sequence = %d", got)
	}
}

func TestReplaceAllowSetsRejectsBoundsBeforeSocket(t *testing.T) {
	addresses := make([]netip.Addr, maxSetElements+1)
	for index := range addresses {
		addresses[index] = netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
	}
	err := ReplaceAllowSets(context.Background(), map[string][]netip.Addr{"allow-test": addresses})
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("error = %v, want element bound", err)
	}
}

func TestConsumeAcknowledgementsAcceptsOnlyExactCappedACK(t *testing.T) {
	expected := ackExpectation(42, 77)
	ack := acknowledgement(expected[42], 77, unix.NLM_F_CAPPED, 0, nil)
	if err := consumeAcknowledgements(ack, 77, expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != 0 {
		t.Fatalf("unconsumed acknowledgements: %v", expected)
	}
}

func TestConsumeAcknowledgementsRejectsMalformedMessages(t *testing.T) {
	tests := []struct {
		name string
		ack  []byte
		want string
	}{
		{name: "truncated", ack: []byte{1, 2, 3}, want: "truncated"},
		{name: "flags", ack: acknowledgement(ackExpectation(42, 77)[42], 77, 0, 0, nil), want: "header"},
		{name: "tlv", ack: acknowledgement(ackExpectation(42, 77)[42], 77, unix.NLM_F_CAPPED, 0, []byte{8, 0, 1, 0, 0, 0, 0, 0}), want: "payload length"},
		{name: "sequence", ack: acknowledgement(ackExpectation(43, 77)[43], 77, unix.NLM_F_CAPPED, 0, nil), want: "sequence"},
		{name: "port", ack: acknowledgement(ackExpectation(42, 77)[42], 78, unix.NLM_F_CAPPED, 0, nil), want: "header"},
		{name: "positive", ack: acknowledgement(ackExpectation(42, 77)[42], 77, unix.NLM_F_CAPPED, 1, nil), want: "positive"},
		{name: "kernel error", ack: acknowledgement(ackExpectation(42, 77)[42], 77, unix.NLM_F_CAPPED, -int32(unix.EPERM), nil), want: "failed"},
		{name: "embedded", ack: acknowledgement(expectedAck{length: 99, typeCode: 88, flags: 77, sequence: 42, portID: 77}, 77, unix.NLM_F_CAPPED, 0, nil), want: "does not match"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := consumeAcknowledgements(test.ack, 77, ackExpectation(42, 77))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func acknowledgement(request expectedAck, replyPortID uint32, flags uint16, code int32, extra []byte) []byte {
	payload := make([]byte, cappedAckPayloadLen, cappedAckPayloadLen+len(extra))
	binary.NativeEndian.PutUint32(payload, uint32(code))
	binary.NativeEndian.PutUint32(payload[4:8], request.length)
	binary.NativeEndian.PutUint16(payload[8:10], request.typeCode)
	binary.NativeEndian.PutUint16(payload[10:12], request.flags)
	binary.NativeEndian.PutUint32(payload[12:16], request.sequence)
	binary.NativeEndian.PutUint32(payload[16:20], request.portID)
	payload = append(payload, extra...)
	return encodeMessage(unix.NLMSG_ERROR, flags, request.sequence, replyPortID, payload)
}

func ackExpectation(sequence, portID uint32) map[uint32]expectedAck {
	return map[uint32]expectedAck{sequence: {
		length: 32, typeCode: nfTablesSubsystemType | unix.NFT_MSG_NEWTABLE,
		flags: createFlags(), sequence: sequence, portID: portID,
	}}
}

func TestWorstCaseNetworkTransactionIsBounded(t *testing.T) {
	var operations []operation
	for index := 0; index < maxNetworks; index++ {
		operations = append(operations, appendRule("forward", true, interfaceIndex(unix.NFT_META_IIF, index+1), verdict(nfAccept)))
	}
	requests, expected, err := encodeTransaction(operations, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, request := range requests {
		total += len(request)
	}
	if len(expected) != maxNetworks || total > maxTransactionBytes {
		t.Fatalf("messages=%d bytes=%d", len(expected), total)
	}
}

func TestMaximumSetElementMessageIsBounded(t *testing.T) {
	values := make([][4]byte, maxSetElements)
	operation := addSetElements("allow-test", values)
	if size := len(operation.payload) + netlinkHeaderLen; size > maxOperationBytes {
		t.Fatalf("maximum set-element message is %d bytes; limit is %d", size, maxOperationBytes)
	}
}
