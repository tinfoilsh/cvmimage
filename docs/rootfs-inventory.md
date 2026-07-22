# Rootfs Inventory and Manifest Comparison

`scripts/rootfs_manifest.py` inventories an explicitly selected Linux root
directory and compares canonical manifests using the format in
`docs/rootfs-manifest-format.md`. It is a build-time audit tool; nothing in the
runtime image invokes it.

## Inventory

Inventory a read-only mounted baseline artifact:

```bash
scripts/rootfs_manifest.py inventory \
    --root /mnt/cvm-rootfs \
    --output evidence/rootfs-baseline/manifest.tsv
```

`--root` is mandatory. Every root path component and descendant directory is
opened descriptor-relatively with `O_NOFOLLOW`; a symlink in any root ancestor
is fatal. The walker never recurses through a symlink. It snapshots each
directory before and after traversal and fails rather than silently omitting an
added, removed, unreadable, invalid, or concurrently replaced entry.

The root itself is represented by `/`. Every record contains all eight canonical
fields. The inventory includes regular files, directories, symlinks, character
and block devices, FIFOs, and sockets. It records:

- SHA-256 content digests for regular files;
- raw symlink targets as canonical base64, without dereferencing them;
- mode, UID, and GID from `lstat`-equivalent metadata;
- all readable xattrs as sorted canonical JSON, including
  `security.capability` when present;
- device major and minor numbers;
- stable hardlink groups named by the first bytewise path in each group.

The filesystem inventory makes no provenance claim. Package, repository,
artifact, build, generated, and removal evidence must be established later by
the exact locked closure owner; a caller-provided label is not evidence.

Paths and xattr names must be valid UTF-8. Tabs and line terminators in paths are
rejected because the canonical format deliberately has no path escaping layer.
Manifest records are sorted by UTF-8 bytes and always end in a newline. Repeated
inventory of an unchanged tree therefore produces byte-identical output. The
output parent must already exist and every supplied parent component must be a
real directory. Output uses a descriptor-relative, no-follow, exclusive-create
temporary file followed by an atomic descriptor-relative rename; concurrent
writers cannot share or redirect a temporary path.

## Validation

Validate syntax and canonical encoding without accessing a filesystem tree:

```bash
scripts/rootfs_manifest.py validate evidence/rootfs-baseline/manifest.tsv
```

Validation rejects malformed fields, non-canonical numbers or base64, unsorted
or duplicate paths, invalid type/content combinations, non-canonical xattr JSON,
and hardlink groups whose inode-shared type, mode,
ownership, content, or xattrs differ.

## Bidirectional Comparison

Compare a candidate against the baseline:

```bash
scripts/rootfs_manifest.py compare \
    --expected evidence/rootfs-baseline/manifest.tsv \
    --actual build/rootfs-candidate/manifest.tsv
```

The comparison examines the union of both path sets. It reports added and
missing paths as well as changes to every non-path field.
Any difference produces exit status `1`. Invalid input produces exit status
`2`. There is no exception file, wildcard, or ignored-field mode.

Differences are emitted in deterministic path and field order:

```text
difference<TAB>/path<TAB>field<TAB>expected<TAB>actual
```

## Tests

Run the isolated test suite with:

```bash
scripts/test-rootfs-manifest.sh
```

The unprivileged suite covers deterministic output, regular files, directories,
symlinks that point outside the selected root, hardlinks, FIFOs, Unix sockets,
xattrs when supported by the backing filesystem, malformed manifests, exact
bidirectional differences, symlink ancestors, concurrent output writers, and
deterministic directory and metadata mutation races. When run as root, it also
covers fixed ownership, setuid metadata, character and block devices,
concurrent device replacement, and file capabilities when `setcap` is available.

## Current Limitations

- The implementation is Linux-specific and requires `/proc` for race-resistant
  no-follow xattr access on symlinks and special files.
- Xattr enumeration requires permission to read all metadata. Baseline images
  should normally be inventoried as root; permission errors are fatal.
- Files that are actively changing are rejected. Inventory a quiescent,
  read-only mount rather than a live runtime filesystem.
- A hardlink whose other links are outside the selected root is represented by
  the first observed in-root path. The manifest intentionally does not expose
  unstable inode numbers or paths outside its safety boundary.
- ACLs are preserved through their xattrs, but the tool does not produce a
  separate human-readable ACL interpretation.
- This work records privileged files but does not decide whether they are
  permitted. Fail-closed privilege policy belongs to the separate metadata
  policy workstream.
