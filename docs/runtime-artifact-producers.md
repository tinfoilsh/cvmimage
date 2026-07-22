# Runtime artifact producers

This review depends on the public nvattest runtime-artifact producer and the
ordered Bazel runtime-lock, exact source-member extraction, and authenticated
Ubuntu package-member stack. It is based directly on their merged public heads.

The additive Go builder exports five rootfs binaries beside its unchanged
initrd artifact. Nvattest exports its binary, versioned library, and two
assembly-only SONAME declarations. The NVIDIA source build exports exactly
three uncompressed modules beneath `kernel/out/rootfs-artifacts`.

`image/manifests/rootfs-artifacts.lock.tsv` is the reviewed consumer contract.
`make verify-rootfs-artifacts` compares every producer manifest to it in both
directions and verifies source files without following symlinks. It rejects
source xattrs and externally linked files. Host ownership is deliberately
irrelevant; the locked `0:0` ownership is final archive metadata enforced by
the later assembler.

`make nvidia-module-artifacts` first invokes the pinned custom-kernel producer.
The NVIDIA build receives both source trees through read-only mounts, creates
private prepared copies, and publishes only the exact three uncompressed
modules. Its reproducibility target builds two independent custom-kernel source
and output roots before comparing module artifacts byte-for-byte.

These targets do not assemble a rootfs or alter the mkosi shipping path.
Generated producer trees remain excluded from Git and Bazel package discovery.
The consumer exposes only the authenticated `build/runtime-artifacts` package;
all other `build` subtrees plus `kernel/build` and `kernel/out` remain excluded
so producer caches cannot become source inputs or break normal
`bazel test //...` validation.
