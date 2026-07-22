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
one lock without the other.

Current SHA-256 values:

- archive: `9890f3ec91788fb9b5bfdb1d17dcd197ba5352a55b10d6b11b393dc64fc84266`
- manifest: `ffee35909230835001cb2bb86d99633ad37b5c5a84b37166679df1e4c1fd9d17`
