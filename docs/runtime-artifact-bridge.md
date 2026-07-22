# Fixed Runtime Artifact Bridge

`image/manifests/rootfs-artifacts.lock.tsv` is the sole authority for the ten
runtime files and two assembly-only `libnvat` symlinks. The bridge does not
discover artifacts or accept paths from callers.

`make prepare-runtime-artifacts` first runs all three fixed producers and their
existing bidirectional verifier. It then snapshots only the ten regular files
and three producer manifests into `build/runtime-artifacts`. Copying is
descriptor-relative and no-follow, hashes bytes while copying, and rejects
source metadata changes. A literal exports-only `BUILD.bazel` and a marker
binding the checked-in lock digest are published only after the snapshot is
complete.

Preparation serializes writers under a private mode-`0700`
`build/.runtime-artifacts-state` directory and uses mode-`0700` staging. The
repository's established shared-group checkout policy permits an existing
mode-`0775` `build` directory only when it has the repository owner and group;
new build directories are not group-writable. Failed marker-owned staging is
removed, while hostile or unowned staging is preserved.

Before publication or deletion, the bridge reauthenticates the literal
`BUILD.bazel`, all three manifests, the marker, and every artifact byte and
mode. Initial publication uses Linux `renameat2(RENAME_NOREPLACE)`, and
replacement uses `renameat2(RENAME_EXCHANGE)`. Existing or raced unmarked,
malformed, symlinked, differently owned, incorrectly shaped, or byte-mutated
trees are preserved and rejected. There is no non-atomic compatibility
fallback.

The generated package exposes files only to `//image:__pkg__`. Bazel never
runs Make or a producer. A clean build therefore fails until preparation is
explicitly completed. `.bazelignore` excludes the other Make/mkosi producer
trees so `bazel test //...` does not traverse privileged cache content while
the exact `build/runtime-artifacts` package remains visible.

`//image:runtime-artifact-members` independently checks the marker, lock,
three manifests, ten file hashes and modes, fixed provenance, destinations,
and the exact two symlink declarations. It emits only:

- `runtime-artifact-members.tar`, containing twelve byte-sorted members with
  locked modes, ownership `0:0`, timestamp zero, and no directory, hardlink,
  device, xattr, or PAX records;
- `runtime-artifact-members.tsv`, using the canonical eight-field rootfs
  manifest format.

This prerequisite deliberately performs no final rootfs assembly or shipping
wiring.
