# Rootfs Manifest Format

The rootfs inventory and candidate verifier share one canonical tab-separated
manifest format. This format is intended to bind later additive construction
and final-disk verification to one exact measured contract.

## Record format

Comment lines begin with `#`. Blank lines are rejected. Each non-comment line
has exactly eight tab-separated fields:

```text
path type mode uid gid content xattrs hardlink
```

- `path` is an absolute, normalized path. NULs, tabs, newlines, `.` components,
  `..` components, duplicate paths, and paths outside the selected root are
  rejected.
- `type` is one of `file`, `dir`, `symlink`, `char`, `block`, `fifo`, or
  `socket`.
- `mode` is exactly four octal digits and includes permission and special bits.
- `uid` and `gid` are non-negative decimal integers.
- `content` is `sha256:<hex>` for regular files, `target64:<base64>` for
  symlinks, `dev:<major>:<minor>` for device nodes, and `-` otherwise.
- `xattrs` is `-` or a compact JSON object whose sorted keys are xattr names and
  whose values are base64-encoded byte strings.
- `hardlink` is `-` unless a regular file has multiple links. Hardlinked files
  use `path64:<base64>` containing the lexicographically first path in the link
  group. Raw inode numbers are never serialized.

Filesystem inspection cannot establish package or artifact provenance, so this
format deliberately records no caller-asserted provenance field. The later
package/artifact closure owner must bind per-path sources to pinned locks and
exact reports rather than injecting an unverifiable label into this manifest.

Records are emitted in bytewise path order with a final newline. Numeric fields,
JSON encoding, and base64 encoding are canonical. Tools run with a fixed locale
and must produce byte-identical output for the same input tree.

## Comparison rules

Comparison is bidirectional. An undeclared path, missing path, changed type,
mode, owner, group, content, symlink target, xattr, capability, device number, or
hardlink group is a failure. The comparison interface has no exception or
ignored-field mechanism.

The verifier rejects setuid, setgid, file capabilities, device nodes, FIFOs, and
sockets unless the source manifest explicitly permits the exact path and value.
The initial additive rootfs policy is expected to permit none of them.

## Safety boundary

Inventory must not follow symlinks and must operate on an explicitly selected
root directory or read-only mounted artifact. It uses descriptor-relative,
no-follow traversal for every root component, snapshots directory membership,
opens regular-file candidates non-blocking, immediately verifies the opened
descriptor type, and fails if an entry, metadata, xattrs, or special-device
identity changes while it is inspected. Manifest output uses exclusive
no-follow temporary creation and atomic replacement within an already verified
parent descriptor.
