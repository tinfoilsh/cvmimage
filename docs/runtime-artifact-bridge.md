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

This preparation review publishes the generated package but keeps the entire
`build` tree outside Bazel package discovery. The following consumer review
narrows that exclusion to expose only authenticated `build/runtime-artifacts`,
with files visible only to `//image:__pkg__`. Bazel never runs Make or a
producer.
