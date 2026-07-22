# Final rootfs byte locks

`rootfs.expected.tsv` and `rootfs.archive.sha256` authenticate the exact
rootfs output assembled from the current producer, bridge, policy, and assembly
review stack. They must be regenerated after the stack is rebased onto merged
public ancestry before release. The archive gate verifies the generated
manifest and archive bytes,
then revalidates the fixed contract while materializing in an isolated
namespace.

Regenerate both locks from the same clean `//image:rootfs` build whenever an
authenticated input intentionally changes. Review the manifest diff, replace
the archive digest, and rerun `//image:final-rootfs-archive-gate`; never update
one lock without the other. Read the authoritative values directly from
`rootfs.archive.sha256` and `rootfs.expected.tsv`; do not duplicate them in
documentation.
