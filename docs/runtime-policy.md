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

Container configuration is fail closed by default. Non-admin workloads cannot request
host IPC, host PID namespaces, raw host devices, arbitrary containerd runtime
aliases, or capability additions outside `IPC_LOCK`, `NET_BIND_SERVICE`, and
`SYS_NICE`. The NVIDIA runtime requires an explicit GPU selection bounded by
the attested top-level GPU count; boolean, zero, negative, duplicate, and
out-of-range selections are rejected.

## CVM administrator containers

`cvm_admin: true` in the measured container config selects a fixed administrative
profile: UID/GID `0:0`, Docker privileged mode, host PID/network namespaces,
no-new-privileges explicitly disabled, the Docker socket at
`/var/run/docker.sock`, and the CVM filesystem at `/host`. Its container rootfs
defaults to writable (`read_only: true` can still be requested). This is
administration of the **whole CVM**, including its workloads, secrets, and guest
firewall, not a stronger form of isolated container root. Kernel module loading
remains locked, and the verified CVM root disk is not made writable.

Admin containers must omit `networks` and `ports`. They share the CVM's interfaces,
routes, and loopback; listeners bind directly to CVM ports. Declare TCP ingress
through `cvm-network.inbound-ports` and arrange any upstream forwarding separately.
Avoid CVM service ports such as 443. The shim uses loopback instead of `shim-net`
when its upstream is an admin container. Other containers and CONNECT allowlists
retain their existing network policy. Guest egress rules are not a security
boundary against the administrator.

Persistence is unchanged: Docker's writable layers, downloaded images, and
ordinary Docker volumes live in RAM and do not survive CVM reboot. Only an
attached storage volume provides durable workspace data after reattachment and
unlock. Container restart retains its writable layer; container recreation does
not. No volume is required for an entirely ephemeral admin environment.

Use the volume's canonical CVM path inside the admin container as well, so Docker
bind mounts and Compose resolve the same files as the shell. A container-only
`/workspace` alias is not a path in the Docker daemon's filesystem. For example,
the following fragment supplements the normal pinned-image, shim and SSH-key
configuration (the image must supply an authenticated SSH server on port 2222):

```yaml
cvm-network:
  inbound-ports: [2222]
volumes:
  - name: workspace
    owner: 0
    exec: true
containers:
  - name: sandbox
    image: <digest-pinned SSH image>
    cvm_admin: true
    working_dir: /run/tinfoil/volumedata/workspace
    volumes: [workspace:/run/tinfoil/volumedata/workspace]
```

Admin permission does not enable debug mode, its config-reload API, console, or
host-supplied-secret exception. Existing debug-toolbox injection is unchanged.
The hosting service must use a `tinfoil-config` version that accepts `cvm_admin`;
older CVM images reject the field. Approve the new measured config before releasing
keys to it, and bind SSH authorization to an owner-controlled source.

## Ordinary workloads

A container may publish TCP ports with `ports: ["<host>:<container>"]`, which
requires an attached network for Docker to translate onto, a host port no other
container claims, and one the CVM does not listen on itself (443, 80, and the
debug toolbox's 2222). The measurement says nothing about the published service's
own integrity or confidentiality; keeping it free of runtime vulnerabilities
is the deployer's job.

Every container image must be an OCI reference containing an immutable digest,
including in measured debug mode. The container manager pulls that exact
reference and verifies Docker's inspected repository digests before creating
the container; mutable tag-only references are always rejected during
configuration validation.

Encrypted models require an explicit `containers[].models` grant. Boot mounts
granted models outside the shared public ramdisk and the container manager
binds each model read-only at `/tinfoil/models/<name>` only in the named
containers. Ungranted plaintext model packs retain the legacy shared layout
for compatibility; adding a grant moves them to the isolated layout.
