# Measured runtime policy

`image/rootfs/` contains common fixed files. `inference/rootfs/` and
`sandbox/rootfs/` contain each variant's accounts and configuration. Their Nix
manifests select files and install them byte-for-byte with declared modes and
root ownership. Package extraction, runtime directories, and sysctls have
separate declarations.

Inference's only non-root account is `nvidia-persistenced` with the measured
identity `143:143`. Both accounts are locked and non-login. Sandbox gives root
the pack's bash shell, a home on the workspace volume, and a `*` password
field, which sshd does not treat as locked. Its other account is sshd's
privilege-separation user. Both variants use the same fixed resolver contract
as `tinfoil-boot`.

Each variant declares its services in `cmd/pid1/`, with their commands,
readiness checks, and hardening policies. Required-service tracking uses those
same declarations. PID 1's self-exec child selects the declared policy and
rejects undeclared services before executing them. The shared hardening package
applies the selected capability, filesystem, and syscall restrictions in a fixed order. A nil
capability list preserves the inherited set; an empty list drops all
capabilities. Only inference declares Docker's environment and the container
and egress service policies.

The shim's policy lists the device paths visible under its restricted `/dev`.
The shared policy includes `null`, `tdx_guest`, and `sev-guest`; inference adds
the NVIDIA control devices, capability directory, and numbered GPU and
NVSwitch devices. Sandbox uses the CPU device list. An empty list gives a
service an empty `/dev` and `/sys`. The shared filesystem code contains no
NVIDIA device selection.

Each variant also declares its boot stages. Inference reports GPU attestation,
registry authentication, firewall setup, and container startup. Sandbox
reports workspace and SSH preparation through its `sandbox` stage, without
placeholder inference stages. The shim uses the variant's device-evidence
provider in both observability and proxy serving phases. The provider accepts
only a nonce; inference binds its expected GPU count when configuring the
provider. Boot uses the same contract for keyserver attestation. Sandbox
rejects a nonzero GPU count before supplying its empty evidence provider.

Both variants register authenticated JSON and Prometheus metrics handlers at
`/.well-known/tinfoil-metrics` and `/.well-known/metrics`. Inference preserves
the existing GPU JSON fields and the six Prometheus series with their
`gpu_type` labels. Sandbox exposes CPU metrics without GPU fields or labels.
Only inference registers `/.well-known/tinfoil-containers`. Each Prometheus
handler has its own registry and produces a fresh snapshot for each scrape.

The measured daemon policy includes these mode `0644` files:

- `/etc/containerd/config.toml` disables containerd families outside the Docker
  runtime path, including CRI/sandbox, transfer/image-verifier, tracing,
  restart-monitor, and unused snapshotter plugins. It places mutable daemon
  state below the private ramdisk and is installed only by the additive rootfs.
- `/etc/docker/daemon.json` disables inter-container communication and the
  userland proxy, uses Docker's nftables backend, enables no-new-privileges and
  the containerd snapshotter, and registers only the pinned NVIDIA runtime by
  absolute path. The sandbox image carries neither Docker nor containerd; it
  installs `sandbox/rootfs/etc/nix/nix.conf`, which stacks the read-only
  toolchain pack under the workspace volume as nix's store, and
  `sandbox/rootfs/etc/profile`, which puts that store's profile on the login
  shell's path.
- `/etc/nftables.conf` installs the fail-closed input and forward baseline and
  declares the fixed `http01`, `inbound`, `container_input`, and
  `container_forward` chains. The measured baseline only jumps to them;
  `tinfoil-boot` populates the HTTP-01 chain and `tinfoil-containers`
  populates the inbound and container chains after creating the fixed
  container bridge. The fixed external address and gateway contract has no
  DHCP allowance. Each variant owns a copy of this measured baseline. The
  copies currently retain identical rules, including sandbox's unused
  container chains; moving ownership does not change firewall behavior.
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
Inference selects container secret names and creates the public mount
directories for isolated models. Shared boot adds model-key references,
resolves the combined secret set, and writes the sealed handoff bound to the
measured config digest. Only workload secrets enter the handoff; model keys
stay with boot. The container manager reads the handoff using inference's
secret selection rules.
