# Runtime source locks

This layer defines and authenticates inputs only. It does not assemble a
rootfs, define final destinations, or switch the image build to Bazel. Bazel's runtime
source module extension reads `image/runtime-sources.lock.json` directly, so no
second editable URL or hash declaration exists.

`image/runtime-packages.yaml` is the small reviewed Ubuntu root set. Bazel and
`rules_distroless` resolve its complete Debian dependency closure into the
generated `image/runtime-packages.lock.json`. `MODULE.bazel.lock` pins the
Bzlmod graph. Normal Bazel commands use `--lockfile_mode=error`.

`image/runtime-sources.lock.json` is the sole URL and SHA256 authority for the
conservative Docker and NVIDIA archives. Its generated control and member
metadata proves package identity, complete control-dependency coverage, and the
exact intended runtime members. The sole control-only exception is `adduser`
for `nvidia-persistenced`: fixed rootfs identity data replaces package
maintainer-script account creation. The
Docker source selects only `containerd`, `containerd-shim-runc-v2`, `dockerd`,
and `runc`. The legacy NVIDIA container hook libraries remain because current
container creation still uses Docker `DeviceRequests`. Fabric Manager records
every file supplied by the pinned vendor topology directory.

`runtime_archive` validates every archive path and type, then emits only the
members named by one source record. Every selected member must occur exactly
once with its locked type, mode, content hash or symlink target. Output archives
have sorted paths, zero timestamps, and fixed root ownership. These member
archives are extraction inputs only; no partial rootfs target consumes them.
Each Bazel action handles exactly one fixed source and materializes that source's
payload in memory. For the current lock, the largest compressed input is
86,681,999 bytes and the largest decompressed Debian data archive is 428,175,360
bytes (414,761,615 bytes of selected regular-file content); sources are never
accumulated across one extractor action.

Ubuntu package payloads are narrowed separately by
`image/runtime-package-members.lock.json`. Fixed package IDs map only to public
`@ubuntu_runtime//<package>/amd64:data` labels. The public rules_distroless
`cacerts` rule deterministically derives the single authenticated CA bundle
from its locked package input. The parent `image/runtime-packages.lock.json`
owns upstream `.deb` identity, version, URL, and digest. This package-member
lock authenticates the deterministic package-data outputs derived from those
parent-locked inputs. Its exact fail-closed closure is 35 package-data sources
and 70 selected paths: the CA bundle, OpenSSL configuration, network
configuration and tools, loader chain, and SONAME/target libraries. It excludes
package-manager, shell, locale, gconv, documentation, systemd, ldconfig/cache,
and iptables/xtables executables and frontend packages.

The generated lock files are declarative size exceptions. Lock generation stays
in `scripts/runtime_source_lock.py` and `scripts/update-runtime-locks.sh`;
exact-member extraction logic is in `image/runtime_archive.bzl` and
`scripts/runtime_archive.py`. Repository, action, and tool wiring is in
`MODULE.bazel`, `image/runtime_sources.bzl`, `image/BUILD.bazel`, and
`scripts/BUILD.bazel`.
`scripts/update_runtime_package_members.py` resolves package data twice in
internally owned Bazel output roots, byte-compares both resolutions, and
atomically replaces the package-member lock. Its `--check` mode never writes.

Run `make test-runtime-locks` for offline schema, mutation, package-member,
Bzlmod graph, and checked-lock tests. `make test-runtime-archives` builds both
the non-Ubuntu member archives and all 35 Ubuntu package-member archives. Run
`make verify-runtime-sources` to perform the complete two-pass Ubuntu and
non-Ubuntu re-resolution, redownload every source archive, regenerate package
data twice, and compare all generated files with the checked-in locks without
modifying the worktree. Run `make update-runtime-locks` only when intentionally
rotating an input. The updater creates one private marked `mktemp` parent with
two child trees, requires byte-identical results, and atomically replaces all
checked-in locks.

The workflow installs the official Bazel 8.7.0 Linux x86_64 binary after
checking its pinned SHA256.
