package rtnetlink

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFixedRequestEncoding(t *testing.T) {
	prefix := netip.MustParsePrefix("100.64.0.42/20")
	gateway := netip.MustParseAddr("100.64.0.1")
	tests := []struct {
		name    string
		payload []byte
		want    []byte
	}{
		{
			name:    "link up",
			payload: linkUpPayload(7),
			want: []byte{
				0, 0, 0, 0, 7, 0, 0, 0,
				1, 0, 0, 0, 1, 0, 0, 0,
			},
		},
		{
			name:    "replace address",
			payload: addressPayload(7, prefix),
			want: []byte{
				2, 20, 0, 0, 7, 0, 0, 0,
				8, 0, 2, 0, 100, 64, 0, 42,
				8, 0, 1, 0, 100, 64, 0, 42,
			},
		},
		{
			name:    "replace default route",
			payload: defaultRoutePayload(7, gateway),
			want: []byte{
				2, 0, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0,
				8, 0, 5, 0, 100, 64, 0, 1,
				8, 0, 4, 0, 7, 0, 0, 0,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !slices.Equal(test.payload, test.want) {
				t.Fatalf("payload = %v, want %v", test.payload, test.want)
			}
		})
	}

	request, err := encodeRequest(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, 9, 11, linkUpPayload(7))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		32, 0, 0, 0, 16, 0, 5, 0, 9, 0, 0, 0, 11, 0, 0, 0,
		0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	}
	if !slices.Equal(request, want) {
		t.Fatalf("request = %v, want %v", request, want)
	}
	if _, err := encodeRequest(unix.RTM_NEWLINK, 0, 1, 1, make([]byte, maxRequestBytes)); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestValidateAck(t *testing.T) {
	request, err := encodeRequest(unix.RTM_NEWADDR, unix.NLM_F_REQUEST|unix.NLM_F_ACK, 17, 23, addressPayload(7, netip.MustParsePrefix("100.64.0.42/20")))
	if err != nil {
		t.Fatal(err)
	}
	payload := append(make([]byte, 4), request[:netlinkHeaderLen]...)
	uncappedError := append([]byte{255, 255, 255, 255}, request...)
	cappedError := append([]byte{255, 255, 255, 255}, request[:netlinkHeaderLen]...)
	for _, flags := range []uint16{0, unix.NLM_F_CAPPED} {
		if err := validateAck(testMessage(unix.NLMSG_ERROR, flags, 17, 23, payload), request); err != nil {
			t.Fatalf("valid ACK flags %#x rejected: %v", flags, err)
		}
	}

	for _, flags := range []uint16{0, unix.NLM_F_CAPPED} {
		errorPayload := cappedError
		if flags == 0 {
			errorPayload = uncappedError
		}
		if err := validateAck(testMessage(unix.NLMSG_ERROR, flags, 17, 23, errorPayload), request); !errors.Is(err, unix.EPERM) {
			t.Fatalf("error ACK flags %#x = %v, want EPERM", flags, err)
		}
	}

	tests := []struct {
		name     string
		datagram []byte
	}{
		{"wrong sequence", testMessage(unix.NLMSG_ERROR, 0, 18, 23, payload)},
		{"wrong port", testMessage(unix.NLMSG_ERROR, 0, 17, 24, payload)},
		{"wrong type", testMessage(unix.NLMSG_DONE, 0, 17, 23, payload)},
		{"unknown flags", testMessage(unix.NLMSG_ERROR, unix.NLM_F_MULTI, 17, 23, payload)},
		{"ACK TLVs", testMessage(unix.NLMSG_ERROR, unix.NLM_F_ACK_TLVS, 17, 23, payload)},
		{"capped ACK TLVs", testMessage(unix.NLMSG_ERROR, unix.NLM_F_CAPPED|unix.NLM_F_ACK_TLVS, 17, 23, payload)},
		{"short error", testMessage(unix.NLMSG_ERROR, 0, 17, 23, payload[:4])},
		{"uncapped error missing request", testMessage(unix.NLMSG_ERROR, 0, 17, 23, cappedError)},
		{"capped error includes request", testMessage(unix.NLMSG_ERROR, unix.NLM_F_CAPPED, 17, 23, uncappedError)},
		{"extra message", append(testMessage(unix.NLMSG_ERROR, 0, 17, 23, payload), testMessage(unix.NLMSG_ERROR, 0, 17, 23, payload)...)},
		{"positive error", testMessage(unix.NLMSG_ERROR, 0, 17, 23, append([]byte{1, 0, 0, 0}, request[:netlinkHeaderLen]...))},
	}
	badEmbedded := append([]byte(nil), payload...)
	badEmbedded[8]++
	badOriginal := append([]byte(nil), uncappedError...)
	badOriginal[len(badOriginal)-1]++
	tests = append(tests, struct {
		name     string
		datagram []byte
	}{"mismatched request", testMessage(unix.NLMSG_ERROR, 0, 17, 23, badEmbedded)})
	tests = append(tests, struct {
		name     string
		datagram []byte
	}{"altered original request", testMessage(unix.NLMSG_ERROR, 0, 17, 23, badOriginal)})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateAck(test.datagram, request); err == nil {
				t.Fatal("malformed ACK accepted")
			}
		})
	}
}

func TestValidateDump(t *testing.T) {
	address := addressPayload(7, netip.MustParsePrefix("100.64.0.42/20"))
	data := testMessage(unix.RTM_NEWADDR, unix.NLM_F_MULTI, 31, 41, address)
	done := testMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, 31, 41, nil)
	request := dumpRequest(t, 31, 41)
	payloads, complete, err := validateDump(append(data, done...), request, unix.RTM_NEWADDR)
	if err != nil || !complete || len(payloads) != 1 || !slices.Equal(payloads[0], address) {
		t.Fatalf("valid dump = payloads %v, complete %t, err %v", payloads, complete, err)
	}
	payloads, complete, err = validateDump(data, request, unix.RTM_NEWADDR)
	if err != nil || complete || len(payloads) != 1 {
		t.Fatalf("partial dump = payloads %v, complete %t, err %v", payloads, complete, err)
	}

	errorRequest, err := encodeRequest(unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, 31, 41, make([]byte, ifAddrMessageLen))
	if err != nil {
		t.Fatal(err)
	}
	errorPayload := append([]byte{254, 255, 255, 255}, errorRequest...)
	for _, flags := range []uint16{0, unix.NLM_F_CAPPED} {
		payload := append([]byte{254, 255, 255, 255}, errorRequest[:netlinkHeaderLen]...)
		if flags == 0 {
			payload = errorPayload
		}
		_, _, err = validateDump(testMessage(unix.NLMSG_ERROR, flags, 31, 41, payload), request, unix.RTM_NEWADDR)
		if !errors.Is(err, unix.ENOENT) {
			t.Fatalf("dump error flags %#x = %v, want ENOENT", flags, err)
		}
	}

	tests := []struct {
		name     string
		datagram []byte
	}{
		{"wrong sequence", testMessage(unix.RTM_NEWADDR, unix.NLM_F_MULTI, 32, 41, address)},
		{"wrong type", testMessage(unix.RTM_NEWROUTE, unix.NLM_F_MULTI, 31, 41, address)},
		{"missing multipart", testMessage(unix.RTM_NEWADDR, 0, 31, 41, address)},
		{"interrupted", testMessage(unix.RTM_NEWADDR, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, 31, 41, address)},
		{"terminator not final", append(done, data...)},
		{"bad done payload", testMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, 31, 41, []byte{1, 2})},
		{"positive done error", testMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, 31, 41, []byte{1, 0, 0, 0})},
		{"dump error ACK TLVs", testMessage(unix.NLMSG_ERROR, unix.NLM_F_ACK_TLVS, 31, 41, errorPayload)},
		{"dump error capped ACK TLVs", testMessage(unix.NLMSG_ERROR, unix.NLM_F_CAPPED|unix.NLM_F_ACK_TLVS, 31, 41, errorPayload)},
		{"dump error unknown flags", testMessage(unix.NLMSG_ERROR, unix.NLM_F_MULTI, 31, 41, errorPayload)},
		{"truncated header", []byte{1, 2, 3}},
	}
	badErrorPayload := append([]byte(nil), errorPayload...)
	badErrorPayload[12]++
	tests = append(tests, struct {
		name     string
		datagram []byte
	}{"mismatched dump error", testMessage(unix.NLMSG_ERROR, 0, 31, 41, badErrorPayload)})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := validateDump(test.datagram, request, unix.RTM_NEWADDR); err == nil {
				t.Fatal("malformed dump accepted")
			}
		})
	}
}

func TestFlushReplyFiltering(t *testing.T) {
	address := addressPayload(7, netip.MustParsePrefix("100.64.0.42/20"))
	if matched, err := addressMatchesInterface(address, 7); err != nil || !matched {
		t.Fatalf("address match = %t, %v", matched, err)
	}
	if matched, err := addressMatchesInterface(address, 8); err != nil || matched {
		t.Fatalf("other address match = %t, %v", matched, err)
	}
	badAddress := append([]byte(nil), address...)
	badAddress[8] = 3
	if _, err := addressMatchesInterface(badAddress, 7); err == nil {
		t.Fatal("malformed address attribute accepted")
	}

	route := defaultRoutePayload(7, netip.MustParseAddr("100.64.0.1"))
	if matched, err := routeMatchesInterface(route, 7); err != nil || !matched {
		t.Fatalf("route match = %t, %v", matched, err)
	}
	otherTable := append([]byte(nil), route...)
	otherTable[4] = unix.RT_TABLE_LOCAL
	if matched, err := routeMatchesInterface(otherTable, 7); err != nil || matched {
		t.Fatalf("local-table route match = %t, %v", matched, err)
	}
	duplicateOutput := append(append([]byte(nil), route...), route[20:28]...)
	if _, err := routeMatchesInterface(duplicateOutput, 7); err == nil {
		t.Fatal("duplicate output-interface attribute accepted")
	}
}

func TestMessageFramingRejectsMalformedLengthsAndPadding(t *testing.T) {
	valid := testMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, 1, 2, []byte{0})
	tests := [][]byte{
		append([]byte(nil), valid[:15]...),
		append([]byte{15, 0, 0, 0}, valid[4:]...),
		append([]byte{255, 255, 255, 127}, valid[4:]...),
	}
	nonzeroPadding := append([]byte(nil), valid...)
	nonzeroPadding[len(nonzeroPadding)-1] = 1
	tests = append(tests, nonzeroPadding)
	for _, datagram := range tests {
		if _, err := parseMessages(datagram); err == nil {
			t.Fatalf("malformed datagram accepted: %v", datagram)
		}
	}
}

func dumpRequest(t *testing.T, sequence, portID uint32) []byte {
	t.Helper()
	request, err := encodeRequest(unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, sequence, portID, make([]byte, ifAddrMessageLen))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testMessage(typeCode, flags uint16, sequence, portID uint32, payload []byte) []byte {
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
