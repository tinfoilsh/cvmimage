package netfilter

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

const (
	nftDatatypeIPv4Address = 7
	ipv4AddressLength      = 4
	ipv6AddressLength      = 16
	ipv4DestinationOffset  = 16
	ipv6DestinationOffset  = 24
	tcpDestinationOffset   = 2
)

func newChain(name string, attrs []byte) operation {
	payload := append(attribute(unix.NFTA_CHAIN_TABLE, cstring(tableName)), attribute(unix.NFTA_CHAIN_NAME, cstring(name))...)
	payload = append(payload, attrs...)
	return message(unix.NFT_MSG_NEWCHAIN, createFlags(), unix.NFPROTO_INET, payload)
}

func baseChain(name string, hook uint32, policy uint32) operation {
	hookAttrs := append(attribute(unix.NFTA_HOOK_HOOKNUM, be32(hook)), attribute(unix.NFTA_HOOK_PRIORITY, be32(0))...)
	attrs := append(nested(unix.NFTA_CHAIN_HOOK, hookAttrs), attribute(unix.NFTA_CHAIN_POLICY, be32(policy))...)
	attrs = append(attrs, attribute(unix.NFTA_CHAIN_TYPE, cstring("filter"))...)
	return newChain(name, attrs)
}

func appendRule(chain string, appendAtEnd bool, expressions ...expression) operation {
	list := make([]byte, 0, len(expressions)*32)
	for _, group := range expressions {
		for _, item := range group {
			list = append(list, nested(unix.NFTA_LIST_ELEM, item)...)
		}
	}
	attrs := append(attribute(unix.NFTA_RULE_TABLE, cstring(tableName)), attribute(unix.NFTA_RULE_CHAIN, cstring(chain))...)
	attrs = append(attrs, nested(unix.NFTA_RULE_EXPRESSIONS, list)...)
	flags := createFlags()
	if appendAtEnd {
		flags |= unix.NLM_F_APPEND
	}
	return message(unix.NFT_MSG_NEWRULE, flags, unix.NFPROTO_INET, attrs)
}

func flushChain(chain string) operation {
	attrs := append(attribute(unix.NFTA_RULE_TABLE, cstring(tableName)), attribute(unix.NFTA_RULE_CHAIN, cstring(chain))...)
	return message(unix.NFT_MSG_DELRULE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, unix.NFPROTO_INET, attrs)
}

func newIPv4Set(name string, setID uint32) operation {
	attrs := append(attribute(unix.NFTA_SET_TABLE, cstring(tableName)), attribute(unix.NFTA_SET_NAME, cstring(name))...)
	attrs = append(attrs, attribute(unix.NFTA_SET_FLAGS, be32(0))...)
	attrs = append(attrs, attribute(unix.NFTA_SET_KEY_TYPE, be32(nftDatatypeIPv4Address))...)
	attrs = append(attrs, attribute(unix.NFTA_SET_KEY_LEN, be32(ipv4AddressLength))...)
	attrs = append(attrs, attribute(unix.NFTA_SET_ID, be32(setID))...)
	return message(unix.NFT_MSG_NEWSET, createFlags(), unix.NFPROTO_INET, attrs)
}

func flushSet(name string) operation {
	attrs := append(attribute(unix.NFTA_SET_ELEM_LIST_TABLE, cstring(tableName)), attribute(unix.NFTA_SET_ELEM_LIST_SET, cstring(name))...)
	return message(unix.NFT_MSG_DELSETELEM, unix.NLM_F_REQUEST|unix.NLM_F_ACK, unix.NFPROTO_INET, attrs)
}

func addSetElements(name string, values [][4]byte) operation {
	elements := make([]byte, 0, len(values)*16)
	for _, value := range values {
		key := nested(unix.NFTA_SET_ELEM_KEY, attribute(unix.NFTA_DATA_VALUE, value[:]))
		elements = append(elements, nested(unix.NFTA_LIST_ELEM, key)...)
	}
	attrs := append(attribute(unix.NFTA_SET_ELEM_LIST_TABLE, cstring(tableName)), attribute(unix.NFTA_SET_ELEM_LIST_SET, cstring(name))...)
	attrs = append(attrs, nested(unix.NFTA_SET_ELEM_LIST_ELEMENTS, elements)...)
	return message(unix.NFT_MSG_NEWSETELEM, createFlags(), unix.NFPROTO_INET, attrs)
}

func expressionNamed(name string, data []byte) expression {
	return expression{append(attribute(unix.NFTA_EXPR_NAME, cstring(name)), nested(unix.NFTA_EXPR_DATA, data)...)}
}

func interfaceIndex(key uint32, index int) expression {
	return combine(metaByte(key), compare(native32(uint32(index)), unix.NFT_CMP_EQ))
}

func metaByte(key uint32) expression {
	data := append(attribute(unix.NFTA_META_KEY, be32(key)), attribute(unix.NFTA_META_DREG, be32(unix.NFT_REG_1))...)
	return expressionNamed("meta", data)
}

func networkProtocol(family byte) expression {
	return combine(metaByte(unix.NFT_META_NFPROTO), compare([]byte{family}, unix.NFT_CMP_EQ))
}

func payloadByte(base uint32, offset, length uint32) expression {
	return payload(base, offset, length, unix.NFT_REG_1)
}

func payloadAddress(family byte, register uint32) expression {
	if family == unix.NFPROTO_IPV4 {
		return payload(unix.NFT_PAYLOAD_NETWORK_HEADER, ipv4DestinationOffset, ipv4AddressLength, register)
	}
	return payload(unix.NFT_PAYLOAD_NETWORK_HEADER, ipv6DestinationOffset, ipv6AddressLength, register)
}

func payload(base, offset, length, register uint32) expression {
	data := append(attribute(unix.NFTA_PAYLOAD_DREG, be32(register)), attribute(unix.NFTA_PAYLOAD_BASE, be32(base))...)
	data = append(data, attribute(unix.NFTA_PAYLOAD_OFFSET, be32(offset))...)
	data = append(data, attribute(unix.NFTA_PAYLOAD_LEN, be32(length))...)
	return expressionNamed("payload", data)
}

func tcpDestinationPort(port uint16) expression {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, port)
	return combine(metaByte(unix.NFT_META_L4PROTO), compare([]byte{unix.IPPROTO_TCP}, unix.NFT_CMP_EQ),
		payload(unix.NFT_PAYLOAD_TRANSPORT_HEADER, tcpDestinationOffset, 2, unix.NFT_REG_1), compare(value, unix.NFT_CMP_EQ))
}

func conntrackStates(mask uint32) expression {
	return conntrackValue(unix.NFT_CT_STATE, mask)
}

func conntrackStatus(mask uint32) expression {
	return conntrackValue(unix.NFT_CT_STATUS, mask)
}

func conntrackValue(key, mask uint32) expression {
	data := append(attribute(unix.NFTA_CT_KEY, be32(key)), attribute(unix.NFTA_CT_DREG, be32(unix.NFT_REG_1))...)
	return combine(expressionNamed("ct", data), bitwise(unix.NFT_REG_1, unix.NFT_REG_1, native32(mask)), compare(native32(0), unix.NFT_CMP_NEQ))
}

func compare(value []byte, operation uint32) expression {
	return compareRegister(unix.NFT_REG_1, value, operation)
}

func bitwise(source, destination uint32, mask []byte) expression {
	xor := make([]byte, len(mask))
	data := append(attribute(unix.NFTA_BITWISE_SREG, be32(source)), attribute(unix.NFTA_BITWISE_DREG, be32(destination))...)
	data = append(data, attribute(unix.NFTA_BITWISE_LEN, be32(uint32(len(mask))))...)
	data = append(data, nested(unix.NFTA_BITWISE_MASK, attribute(unix.NFTA_DATA_VALUE, mask))...)
	data = append(data, nested(unix.NFTA_BITWISE_XOR, attribute(unix.NFTA_DATA_VALUE, xor))...)
	return expressionNamed("bitwise", data)
}

func lookup(name string, setID, register uint32) expression {
	data := append(attribute(unix.NFTA_LOOKUP_SET, cstring(name)), attribute(unix.NFTA_LOOKUP_SREG, be32(register))...)
	data = append(data, attribute(unix.NFTA_LOOKUP_SET_ID, be32(setID))...)
	return expressionNamed("lookup", data)
}

func verdict(code int32) expression {
	return immediateVerdict(code, "")
}

func verdictJump(chain string) expression {
	return immediateVerdict(unix.NFT_JUMP, chain)
}

func immediateVerdict(code int32, chain string) expression {
	verdictData := attribute(unix.NFTA_VERDICT_CODE, be32(uint32(code)))
	if chain != "" {
		verdictData = append(verdictData, attribute(unix.NFTA_VERDICT_CHAIN, cstring(chain))...)
	}
	data := append(attribute(unix.NFTA_IMMEDIATE_DREG, be32(unix.NFT_REG_VERDICT)), nested(unix.NFTA_IMMEDIATE_DATA, nested(unix.NFTA_DATA_VERDICT, verdictData))...)
	return expressionNamed("immediate", data)
}

func publicDestinationRule(interfaceIndexValue int, family byte, blocked []netip.Prefix) (operation, error) {
	if family != unix.NFPROTO_IPV4 && family != unix.NFPROTO_IPV6 {
		return operation{}, fmt.Errorf("unsupported network family %d", family)
	}
	expressions := []expression{interfaceIndex(unix.NFT_META_IIF, interfaceIndexValue), networkProtocol(family), payloadAddress(family, unix.NFT_REG_1)}
	for _, prefix := range blocked {
		if prefix.Addr().Is4() != (family == unix.NFPROTO_IPV4) {
			return operation{}, fmt.Errorf("prefix %s does not match network family %d", prefix, family)
		}
		mask, network := prefixBytes(prefix)
		expressions = append(expressions, bitwise(unix.NFT_REG_1, unix.NFT_REG_2, mask), compareRegister(unix.NFT_REG_2, network, unix.NFT_CMP_NEQ))
	}
	expressions = append(expressions, verdict(nfAccept))
	return appendRule("forward", true, expressions...), nil
}

func prefixRule(interfaceIndexValue int, prefix netip.Prefix, code int32) operation {
	family := byte(unix.NFPROTO_IPV6)
	if prefix.Addr().Is4() {
		family = unix.NFPROTO_IPV4
	}
	mask, network := prefixBytes(prefix)
	return appendRule("forward", true, interfaceIndex(unix.NFT_META_IIF, interfaceIndexValue), networkProtocol(family),
		payloadAddress(family, unix.NFT_REG_1), bitwise(unix.NFT_REG_1, unix.NFT_REG_1, mask), compare(network, unix.NFT_CMP_EQ), verdict(code))
}

func compareRegister(register uint32, value []byte, operation uint32) expression {
	data := append(attribute(unix.NFTA_CMP_SREG, be32(register)), attribute(unix.NFTA_CMP_OP, be32(operation))...)
	data = append(data, nested(unix.NFTA_CMP_DATA, attribute(unix.NFTA_DATA_VALUE, value))...)
	return expressionNamed("cmp", data)
}

func prefixBytes(prefix netip.Prefix) ([]byte, []byte) {
	prefix = prefix.Masked()
	length := 16
	address := prefix.Addr().As16()
	network := address[:]
	if prefix.Addr().Is4() {
		length = 4
		value := prefix.Addr().As4()
		network = value[:]
	}
	mask := make([]byte, length)
	for bit := 0; bit < prefix.Bits(); bit++ {
		mask[bit/8] |= 1 << (7 - bit%8)
	}
	return mask, append([]byte(nil), network...)
}

func combine(expressions ...expression) expression {
	var result expression
	for _, item := range expressions {
		result = append(result, item...)
	}
	return result
}
