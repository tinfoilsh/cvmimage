# Runtime input locks

This layer pins runtime inputs. It does not assemble a rootfs, filter package
contents, or claim to authenticate a builder.

`image/runtime-packages.yaml` is the reviewed Ubuntu package manifest. It pins
the dated `20260721T000000Z` snapshot and exact requested package versions.
`rules_distroless` resolves the complete dependency closure into
`image/runtime-packages.lock.json`, including each package URL and SHA-256.
Each `@ubuntu_runtime//PACKAGE:data` target exposes one complete normalized
package payload. `_RUNTIME_PACKAGE_LAYERS` in `image/BUILD.bazel` is the fixed
measured-rootfs assembly selection; it uses those complete data layers without
path filtering or archive repacking. `debconf` and `libcap2-bin` remain in the
canonical lock as dependency provenance, but their administrative payloads are
intentionally absent from `_RUNTIME_PACKAGE_LAYERS` and the measured rootfs.

`image/runtime-sources.lock.json` contains ordinary URL and SHA-256 locks for
Docker and NVIDIA archives that cannot be represented by the Ubuntu apt
resolver. The module extension downloads each archive with Bazel's built-in
digest verification. It exposes the complete Docker payload and uses the
existing `rules_distroless` complete-payload normalization for NVIDIA Debian
packages. It does not filter package paths or execute maintainer scripts.

The NVIDIA CUDA repository uses a flat apt layout that `rules_distroless`
0.8.0 cannot resolve. Its package URLs and digests therefore remain in the
ordinary source lock instead of a resolver-generated apt lock.

`.bazelversion` pins Bazel 8.7.0 and `MODULE.bazel.lock` pins the Bzlmod graph.
Run `make test-runtime-locks` for the package-lock comparison and locked module
graph. Run `make verify-runtime-sources` to regenerate the Ubuntu package lock
twice and compare it with the checked-in file. Run `make update-runtime-locks`
only when intentionally rotating the package manifest. Regenerate
`MODULE.bazel.lock` from the real workspace with
`bazel mod deps --lockfile_mode=update` when module dependencies change.
