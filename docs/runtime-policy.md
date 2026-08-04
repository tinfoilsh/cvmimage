# Measured runtime policy

`image/rootfs` contains fixed files that the additive rootfs copies byte-for-byte
as root-owned declarations. It does not define package extraction, runtime
directories, sysctls, systemd policy, or NVIDIA compatibility behavior.

The only non-root account is `nvidia-persistenced` with the measured identity
`143:143`. The root and `nvidia-persistenced` accounts are locked and
non-login. Resolver bytes must remain identical to the fixed resolver contract
used by `tinfoil-boot`.

The measured daemon policy includes these mode `0644` files:

- `/etc/containerd/config.toml` disables containerd families outside the Docker
  runtime path, including CRI/sandbox, transfer/image-verifier, tracing,
  restart-monitor, and unused snapshotter plugins. It places mutable daemon
  state below the private ramdisk and is installed only by the additive rootfs.
- `/etc/docker/daemon.json` disables inter-container communication and the
  userland proxy, uses Docker's nftables backend, enables no-new-privileges and
  the containerd snapshotter, and registers only the pinned NVIDIA runtime by
  absolute path.
- `/etc/nftables.conf` installs the fail-closed input and forward baseline and
  declares the fixed `http01`, `inbound`, `container_input`, and
  `container_forward` chains. The measured baseline only jumps to them;
  `tinfoil-boot` populates the HTTP-01 chain and `tinfoil-containers`
  populates the inbound and container chains after creating the fixed
  container bridge. The fixed external address and gateway contract has no
  DHCP allowance.
- `/etc/nvidia-container-runtime/config.toml` prevents runtime module loading,
  exposes only compute and utility capabilities, invokes only the pinned
  `runc` path, consumes only `/var/run/cdi` specifications, and rejects
  container-selected `ldconfig` execution. Its `@/sbin/ldconfig` value is
  host-relative under the pinned toolkit contract and resolves to the
  `ldconfig` executable provided by Ubuntu's required `libc-bin` package.
- `/usr/share/nvidia/nvswitch/fabricmanager.cfg` preserves the pinned package
  configuration except for two deviations: it disables daemonization and sets
  the fixed command socket to `/run/nvidia-fabricmanager/socket`. PID 1
  invokes Fabric Manager directly as a supervised foreground process and
  requires both its live PID file and this Unix socket before continuing.

The NVIDIA bootstrap publishes `/var/run/cdi/nvidia.yaml` atomically for the
runtime's fixed `nvidia.com/gpu` CDI kind. Legacy, CSV, hook compatibility, and
alternate OCI runtimes are not configured.

Production container configuration is fail closed. Workloads cannot request
host IPC, host PID namespaces, raw host devices, arbitrary containerd runtime
aliases, or capability additions outside `IPC_LOCK`, `NET_BIND_SERVICE`, and
`SYS_NICE`. The NVIDIA runtime requires an explicit GPU selection bounded by
the attested top-level GPU count; boolean, zero, negative, duplicate, and
out-of-range selections are rejected.

Outside measured debug mode, every container image must be an OCI reference
containing an immutable digest. The container manager pulls that exact
reference and verifies Docker's inspected repository digests before creating
the container; mutable tag-only references are rejected during configuration
validation.

Images used in production must not define Docker health checks, volumes, or
NVIDIA control environment variables. The container manager disables inherited
health checks when no measured health check is configured, overwrites NVIDIA
visibility and capability variables with its measured values, and inspects each
newly created container before start. Any effective privileged mode, namespace,
runtime, device, capability, security-option, volume, health-check, or NVIDIA
environment value that differs from the measured request causes the stopped
container to be removed. Health-check output is not copied into boot status or
the host console; only the exit status is reported.

The public ramdisk is not mounted wholesale into workloads. Every container
receives only the public configuration, attestation, and container-status files
at their fixed `/tinfoil` paths. Model packs require an explicit container
`models` assignment and only those verified model mount points are bound into
that container, including the legacy `mpk` alias for the same selected pack.

Production root filesystems remain read-only. Mutable storage uses Docker named
volumes mounted only at `/data` or a clean path below it, with an explicit `ro`
or `rw` mode when desired. A named volume can have at most one writable
container owner; additional consumers must mount it read-only. Raw host bind
sources supplied by workload configuration remain reserved for the measured
debug toolbox; fixed public files and explicitly assigned verified models use
first-party read-only binds. Configured tmpfs mounts are restricted to `/tmp`
or a clean path below it.

Every managed Docker bridge is created with inter-container communication
disabled, and an existing bridge is reused only when its driver, Linux bridge
name, and ICC setting match the measured policy. The nftables policy does not
add a same-bridge forwarding exception, so containers sharing a logical network
do not gain lateral connectivity merely by joining that bridge.

Hostname-based egress allowlists are rejected in production until enforcement
can bind the authorized hostname to each outbound connection without relying on
mutable DNS-to-IP cache state. Closed and open egress modes remain available;
the legacy allowlist implementation is retained only for measured debug mode.

The public shim treats all caller-supplied proxy identity and credential headers
as untrusted. Before forwarding a decrypted request it removes bearer and proxy
credentials, `Forwarded`, every `X-Forwarded-*` and `X-Real-IP` value, EHBP
transport metadata, and reserved `Tinfoil-*` headers. It then emits only fixed
local `localhost`/HTTPS forwarding metadata; workloads cannot mistake a client
header or validated API key for a trusted internal identity assertion.

Authenticated shim mode is fail closed. It requires a non-empty HTTPS control
plane, a measured `shim.model` identifier, and at least one protected endpoint.
Every credential type, including OAuth JWTs, is sent to the online validator
with the exact `{api_key, model, path}` schema, so per-model blocklists and
path-specific rules cannot be bypassed by a local fast path or omitted model
field. Missing validators return 503 rather than enabling proxy access. Shim
configuration rejects unknown fields, non-canonical paths, and wildcard syntax
other than a single trailing `/*`.

The shim is a request/response proxy, not a general tunnel. It rejects CONNECT,
WebSocket and custom `Upgrade` requests, h2c negotiation, and HTTP2-Settings
before EHBP processing or workload proxying. This prevents an upgraded stream
from escaping the per-request path, authentication, rate-limit, and response
handling policy.
