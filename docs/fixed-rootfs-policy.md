# Fixed measured rootfs policy

`image/rootfs` contains only fixed files that the final additive rootfs copies
byte-for-byte as root-owned declarations. It does not define package
extraction, runtime directories, sysctls, systemd policy, or NVIDIA
compatibility behavior.

The only non-root account is `nvidia-persistenced` with the measured identity
`143:143`. Both accounts are locked and non-login. Resolver bytes must remain
identical to the fixed resolver contract used by `tinfoil-boot`.

The measured daemon policy includes these mode `0644` files:

- `/etc/containerd/config.toml` disables containerd families outside the Docker
  runtime path, including CRI/sandbox, transfer/image-verifier, tracing,
  restart-monitor, and unused snapshotter plugins. It places mutable daemon
  state below the private ramdisk and is installed only by the additive rootfs.
- `/etc/docker/daemon.json` disables inter-container communication and the
  userland proxy, uses Docker's nftables backend, enables no-new-privileges and
  the containerd snapshotter, and registers only the pinned NVIDIA runtime by
  absolute path.
- `/etc/nftables.conf` installs the fail-closed input and forward baseline that
  `tinfoil-boot` augments after creating the fixed container bridge. The fixed
  external address and gateway contract has no DHCP allowance.
- `/etc/nvidia-container-runtime/config.toml` prevents runtime module loading,
  exposes only compute and utility capabilities, invokes only the pinned
  `runc` path, consumes only `/var/run/cdi` specifications, and rejects
  container-selected `ldconfig` execution. Its `@/sbin/ldconfig` value is
  host-relative under the pinned toolkit contract and resolves to the
  `ldconfig` executable provided by Ubuntu's required `libc-bin` package.

The NVIDIA bootstrap publishes `/var/run/cdi/nvidia.yaml` atomically for the
runtime's fixed `nvidia.com/gpu` CDI kind. Legacy, CSV, hook compatibility, and
alternate OCI runtimes are not configured.

- `/usr/share/nvidia/nvswitch/fabricmanager.cfg` preserves the pinned package
  configuration and sets the fixed command socket to
  `/run/nvidia-fabricmanager/socket`. PID 1 invokes Fabric Manager directly and
  requires both its live PID file and this Unix socket before continuing.

The additive rootfs declaration in `image/BUILD.bazel` is the metadata owner.
It installs these source-controlled bytes as UID/GID `0:0` with explicit modes;
there is no second validator that restates their complete path or hash set.
