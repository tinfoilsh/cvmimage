# Additive initrd

The initrd is assembled from an empty staging directory. It is not copied from
an Ubuntu filesystem and then pruned. Its executable is the statically linked
`tinfoil-initrd` binary produced by the isolated mkosi builder. The minimized
kernel contract builds the initrd device-mapper targets in, so the additive
initrd carries no module payload.

## Trust boundary

`builder/` is a disposable Ubuntu builder pinned to the `20260525T000000Z` APT
snapshot. It installs the exact `ca-certificates=20260223` and
`golang-1.25-go=1.25.7-2` build packages. Package transactions and maintainer
scripts run only in that builder. The builder filesystem is never used as an
initrd input. The opt-in builder and reproducibility targets require mkosi v26.

The builder exports only `tinfoil-initrd` and `artifacts.tsv`. Assembly accepts
outputs only when their hashes and destinations match
`image/manifests/artifacts.lock.tsv`. The lock records the reviewable source
tree and build contract; assembly also rejects a source-tree lock mismatch or
uncommitted and ignored files under `tinfoil/`. It rejects undeclared builder
artifacts.

`image/initrd/manifest.tsv` declares every initrd path, type, mode, owner,
symlink target, content artifact, and provenance. `scripts/initrd_manifest.py`
creates a new staging tree, verifies it bidirectionally, writes deterministic
`newc`, and verifies the compressed archive again.

## Commands

Run these commands from the dedicated worktree:

```sh
make builder-initrd
make additive-initrd
make verify-additive-initrd
make test-additive-initrd
make reproducible-additive-initrd
```

Build state and package caches remain under `build/` in the worktree. The final
artifact is `initrd.cpio.zst`.

The additive artifact remains opt-in until the image switch activates the
minimized built-in kernel. The current distro initrd stays wired to the current
stock-kernel image, so this milestone does not create a temporarily unbootable
default build. The direct-roothash follow-up upgrades the release builder to
mkosi v26 only to consume its fixed split roothash artifact; it does not select
this opt-in initrd. No subtractive initrd finalizer is introduced.

The assembler requires Zstandard CLI 1.5.7 and fails closed on another version.
Compression uses one thread, level 19, no progress output, and a fixed input
archive. Archive ordering, inode allocation, owners, modes, timestamps, device
metadata, and padding are generated directly rather than inherited from the
host filesystem.

## Verification

Verification rejects extra or missing paths, incorrect file types or metadata,
path traversal, undeclared parent directories, escaping artifact symlinks, hash
drift, changed or broken symlinks, xattrs and file capabilities, non-rwx mode
bits, dynamic ELF dependencies, special files, kernel-module paths,
non-canonical archive padding, and distro-bootstrap residue. Negative tests
mutate the stage and manifests to prove these failures remain closed.

`make reproducible-additive-initrd` performs two clean builds on the same host
with separate builder directories, package caches, workspaces, staging trees,
and outputs. It requires byte-identical builder binaries and compressed initrds
and writes hashes to `evidence/additive-initrd-reproducibility.txt`. This is
same-host repeatability evidence, not an independent-rebuilder proof.

This milestone covers only the builder binary and additive initrd. The
distro-derived rootfs, TDX components, NVIDIA modules and userspace, and final
disk-image tooling remain deferred and prevent a claim of complete image
bit-for-bit reproducibility.
