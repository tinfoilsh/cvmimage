# Fixed measured rootfs policy

`image/rootfs` contains only fixed files that the final additive rootfs copies
byte-for-byte as root-owned declarations. It does not define package
extraction, runtime directories, sysctls, systemd policy, or NVIDIA
compatibility behavior.

The only non-root account is `nvidia-persistenced` with the measured identity
`143:143`. Both accounts are locked and non-login. Resolver bytes must remain
identical to the fixed resolver contract used by `tinfoil-boot`.

The measured daemon policy consists of exactly four mode `0644` files:

- `/etc/containerd/config.toml` disables unused containerd service families and
  places mutable daemon state below the private ramdisk. This measured file is
  the canonical policy owner; the current `mkosi.extra` installation copy must
  remain byte-identical until the additive rootfs replaces that build input.
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

Fabric Manager configuration is not part of this policy. The current image
receives it from the version-pinned `nvidia-fabricmanager=595.71.05-1ubuntu1`
package selected in `mkosi.conf`; this policy does not claim separate archive
provenance for that package-owned configuration.

`scripts/test-rootfs-policy.sh` verifies the complete path and SHA-256 contract,
not only selected files. The policy root must exactly match the checkout root's
mode, owner, and group because Git does not transport directory metadata. Every
directory must be mode `0755`, every file must be mode `0644`, every entry must
share the checkout root's owner and group, and no entry (including the root
directory) may carry an xattr. The later assembler must preserve those modes
and install every declaration as UID/GID `0:0`. Undeclared entries at any depth
are rejected.
