# Additive initrd

The initrd is one complete Bazel target with one content input:

- `//tinfoil/cmd/initrd:tinfoil-initrd`, built from its fixed pure-Go dependency
  closure with upstream `rules_go`.

`//image/initrd:initrd` runs a small fixed Go `newc` writer through the
structured `bazel_lib` `run_binary` rule. The writer emits only six directories,
the fixed initrd command, and `/init -> usr/bin/tinfoil-initrd`, with constant
ordering and metadata. It streams that archive into the pinned Bazel Zstandard
tool and produces `bazel-bin/image/initrd/initrd.cpio.zst` directly.

There is no manifest language, filesystem walk, generic archive interface,
shell action, custom Starlark rule, extraction mode, or verification parser.
The five CGO-enabled measured runtime commands remain outputs of the pinned
disposable builder and are consumed by their own measured runtime destinations.

The producer intentionally does not consume an artifact-discovery manifest,
lock compiled output hashes, or make provenance claims. Those mechanisms do
not protect against a compromised builder. Source and tool inputs are reviewed
and pinned at their actual producer boundaries. Release qualification boots,
tests, attests, and promotes the exact candidate measurement.

Build-time denial of service is accepted under this threat model. A failed,
slow, or disrupted builder cannot cause a different image to pass runtime
attestation; it can only prevent production of a releasable artifact.

The focused commands are:

```sh
make bazel-initrd
make test-bazel-initrd
```

Repeated full-build comparison is deferred. Release qualification boots,
tests, attests, and promotes the exact candidate image.
