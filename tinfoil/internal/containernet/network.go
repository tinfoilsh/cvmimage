// Package containernet exposes shared constants for in-CVM container
// networks. Both tinfoil-boot and tinfoil-shim reference these to avoid
// drift.
package containernet

// ShimNetName is the implicit Docker network connecting the shim (host
// netns) to its upstream container. Always closed; never declarable by
// the operator.
const ShimNetName = "shim-net"

// AllowSetPrefix is the nftables-set name prefix for an `egress:
// allowlist` network's resolved IPs: allow-<network-name>.
const AllowSetPrefix = "allow-"
