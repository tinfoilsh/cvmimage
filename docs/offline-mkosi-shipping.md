# Offline mkosi shipping

The final image assembly step consumes `build/stage/bazel-rootfs.tar` as its
only root filesystem input. `mkosi.conf` uses `Distribution=custom`, a fixed
seed, `SourceDateEpoch=0`, and offline `systemd-repart` operation. It declares
no packages, repositories, package directories, build scripts, tools tree, or
incremental cache.

mkosi formats the fixed 256 MiB ESP, 8 GiB root, and 1.5 GiB dm-verity
partitions and emits
`tinfoilcvm.raw` plus the authoritative `tinfoilcvm.roothash`. The ESP is
intentionally empty: the platform receives the pinned custom kernel and
additive initrd as separate artifacts, so final assembly does not copy an
unnecessary `/efi` tree into the disk image.

mkosi 26 always invokes its systemd finalization helpers. The additive rootfs
predeclares their two fixed files and a `disable *` preset, so those helpers do
not change runtime policy or image contents. A real extracted-filesystem
comparison leaves only ext4's formatter-owned `lost+found` directory outside
the additive rootfs tar.

`make shipping-image` builds the named producers, additive rootfs, and additive
initrd before invoking mkosi. It then publishes these fixed local outputs:

- `tinfoilcvm.raw` from mkosi;
- `tinfoilcvm.roothash` from mkosi;
- `tinfoilcvm.vmlinuz` from `kernel/out/tinfoil-custom.vmlinuz`;
- `tinfoilcvm.initrd` from `bazel-bin/image/initrd/initrd.cpio.zst`; and
- `tinfoilcvm.hash` as the compatibility copy of the roothash.

The tag workflow performs one ordinary build and publishes those artifacts. It
does not qualify or promote a measurement. Release qualification remains a
protected process outside normal PR and release CI: two isolated builds,
`sha256sum` and `cmp`, optional `diffoscope` only on mismatch, functional
hardware testing, attestation, approval, and promotion of the exact qualified
measurement.
