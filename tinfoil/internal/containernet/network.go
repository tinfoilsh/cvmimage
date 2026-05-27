// Package containernet exposes shared constants for in-CVM container
// networks. Both tinfoil-boot and tinfoil-shim reference these to avoid
// drift.
package containernet

const (
	// ShimNetName is the implicit Docker network connecting the shim (host
	// netns) to its upstream container. Always closed; never declarable by
	// the operator.
	ShimNetName = "shim-net"

	// ShimNetSubnetCIDR is a tiny, fixed subnet reserved for the private
	// shim-to-upstream hop. The shim dials ShimUpstreamIP directly.
	ShimNetSubnetCIDR = "172.31.255.0/30"
	ShimNetGatewayIP  = "172.31.255.1"
	ShimUpstreamIP    = "172.31.255.2"

	// AllowSetPrefix is the nftables-set name prefix for an `egress:
	// allowlist` network's resolved IPs: allow-<network-name>.
	AllowSetPrefix = "allow-"
)
