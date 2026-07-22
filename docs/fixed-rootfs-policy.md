# Fixed measured rootfs policy

`image/rootfs` contains only fixed files that the final additive rootfs copies
byte-for-byte. It does not define package extraction, runtime directories,
sysctls, systemd policy, or NVIDIA compatibility behavior.

The only non-root account is `nvidia-persistenced` with the measured identity
`143:143`. Both accounts are locked and non-login. Resolver bytes must remain
identical to the fixed resolver contract used by `tinfoil-boot`.

`scripts/test-rootfs-policy.sh` verifies the complete `image/rootfs` tree, not
only the declared files. The policy root must exactly match the checkout root's
mode, owner, and group because Git does not transport directory metadata. The
`etc` directory must be mode `0755`, all files must be mode `0644`, every entry
must share the checkout root's owner and group, and no entry (including the root
directory) may carry an xattr. Undeclared entries at any depth are rejected.
