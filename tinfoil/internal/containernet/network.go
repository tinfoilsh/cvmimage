// Package containernet exposes shared constants for the Docker network that
// holds in-CVM workload containers. Both tinfoil-boot (which creates the
// network) and tinfoil-shim (which dials a container on it) reference these,
// so they live here to avoid drift between the two components.
package containernet

// NetworkName is the Docker network name tinfoil-boot creates and joins all
// workload containers to. The shim resolves the upstream container's IP on
// this network.
const NetworkName = "container-net"

// BridgeName is the Linux bridge interface backing NetworkName. Linux caps
// interface names at 15 characters, which is why this matches NetworkName.
const BridgeName = "container-net"
