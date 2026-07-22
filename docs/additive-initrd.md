# Additive initrd

The initrd is constructed from two fixed inputs:

- `image/initrd/manifest.tsv`, which declares the complete archive layout and
  deterministic metadata;
- `build/builder-work/output/artifacts/tinfoil-initrd`, the single named binary
  produced by the shared pinned runtime builder.

The Go compiler and its packages are installed in the disposable builder
image. Package installation and maintainer scripts are allowed there because
the builder filesystem is never copied into the initrd or measured rootfs. The
only builder output accepted by this producer is the fixed
`artifacts/tinfoil-initrd` file.

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
./scripts/build-runtime-builder.sh
./scripts/run-runtime-builder.sh initrd
make additive-initrd
make verify-additive-initrd
make test-additive-initrd
```

Full reproduction is release qualification, not routine pull-request CI. The
release process performs clean repeated builds with separate caches and outputs
and requires the named builder binaries and compressed initrds to be
byte-identical. This is output comparison, not an independent-rebuilder or
provenance proof.
