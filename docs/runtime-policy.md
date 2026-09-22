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

## Attested workload keys

The measured `attested-keys` list declares `{id, key, uid?, gid?}` and each
`containers[].keys` list grants one declared ID to exactly one container.
Algorithms are `ecdsa-p256`, `ed25519`, and `x25519`. Boot generates every key
once per CVM boot in private tmpfs; shim and container restarts keep it and a
reboot rotates it. A grant bind-mounts `/run/tinfoil/keys/<id>` read-only with
`private_key.pem` (PKCS#8, mode 0600) and `public_key.pem` (SPKI) owned by the
measured UID/GID. Every v3 quote endorses each key as a `crypto_material` entry
using the declared ID and `https://tinfoil.sh/key/spki/v1` with full SPKI DER as
lowercase hex. The runtime never emits SSH or other application encodings.

## CVM administrator containers

`cvm_admin: true` in the measured container config selects a fixed administrative
profile: UID/GID `0:0`, Docker privileged mode, and no-new-privileges explicitly
disabled. It does not share host PID/network namespaces or mount host runtime
sockets or the host filesystem. Its container rootfs
defaults to writable (`read_only: true` can still be requested). This is
administration of the **whole CVM**, including its workloads, secrets, and guest
firewall, not a stronger form of isolated container root. Kernel module loading
remains locked, and the verified CVM root disk is not made writable.

Admin containers use declared bridge `networks` and `ports` like ordinary
workloads. An `egress: open` network provides Internet access; published ports
remain loopback-only and reachable through the shim's authenticated, attested
CONNECT tunnel. The one exception is direct SSH, which requires `cvm_admin: true`,
`ports: ["22:22"]`, and `cvm-network.inbound-ports: [22]` together: that mapping
binds on the guest interface and the firewall admits its DNAT traffic. The debug
toolbox keeps port 2222 and suppresses this exception. The host must still
forward a port to guest 22. Images may run an inner Docker daemon: nested containers use its own
bridges/NAT and Unix socket, so `docker ps` does not show the SSH wrapper. Guest
network rules are not a security boundary against the CVM administrator.

Persistence is unchanged: Docker's writable layers, downloaded images, and
ordinary Docker volumes live in RAM and do not survive CVM reboot. Only an
attached storage volume provides durable workspace data after reattachment and
unlock. Container restart retains its writable layer; container recreation does
not. No volume is required for an entirely ephemeral admin environment.

With Docker-in-Docker, bind-mount sources are paths inside the admin container,
so a volume mounted at `/workspace` can be used directly by its inner daemon.
The image owns that daemon's lifecycle and can reset its RAM-backed state on
container restart too. For example,
the following fragment supplements the normal pinned-image, shim and SSH-key
configuration (the image must serve SSH on port 22 with the granted host key):

```yaml
attested-keys:
  - id: host-ssh
    key: ecdsa-p256
cvm-network:
  inbound-ports: [22]
networks:
  dev:
    egress: open
volumes:
  - name: workspace
    owner: 0
    exec: true
containers:
  - name: sandbox
    image: <digest-pinned SSH image>
    cvm_admin: true
    networks: [dev]
    ports: ["22:22"]
    keys: [host-ssh]
    working_dir: /workspace
    volumes: [workspace:/workspace]
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
