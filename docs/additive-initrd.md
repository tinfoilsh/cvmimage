# Additive initrd

The initrd is constructed from two fixed inputs:

- `image/initrd/manifest.tsv`, which declares the complete archive layout and
  deterministic metadata;
- `bazel-bin/tinfoil/cmd/initrd/tinfoil-initrd_/tinfoil-initrd`, built from its
  fixed pure-Go dependency closure with upstream `rules_go`.

The additive-initrd producer accepts only that fixed Bazel output. The five
CGO-enabled measured runtime commands remain outputs of the pinned disposable
builder and are consumed by their own measured runtime destinations.

`scripts/build-additive-initrd.sh` writes a canonical `newc` archive directly
from those inputs, compresses it with Zstandard 1.5.7 using one thread and level
19, and verifies the resulting archive against the same fixed inputs. Archive
ordering, inode numbers, ownership, modes, timestamps, device metadata, and
padding do not depend on a staging filesystem.

The producer intentionally does not consume an artifact-discovery manifest,
lock compiled output hashes, or make provenance claims. Those mechanisms do
not protect against a compromised builder. Source and tool inputs are reviewed
and pinned at their actual producer boundaries, while release qualification
compares independently repeated named outputs.

Build-time denial of service is accepted under this threat model. A failed,
slow, or disrupted builder cannot cause a different image to pass runtime
attestation; it can only prevent production of a releasable artifact.

The focused commands are:

```sh
make additive-initrd
make test-additive-initrd
```

Repeated full-build comparison is deferred. Release qualification boots,
tests, attests, and promotes the exact candidate image.
