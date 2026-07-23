# Simple additive rootfs

The measured root filesystem starts empty and is assembled by
`//image:rootfs` into `bazel-bin/image/bazel-rootfs.tar`.
`make bazel-rootfs` runs the required fixed named producers, verifies and stages
the fixed content-addressed nvattest cache artifacts, and installs that archive
at `build/stage/bazel-rootfs.tar` for the offline mkosi shipping step.

The target combines, in fixed order:

1. complete normalized payloads from every package in the locked Ubuntu and
   NVIDIA package sets;
2. the complete locked Docker static archive payload;
3. repository-owned files under `image/rootfs` with explicit mode, UID and
   GID;
4. the fixed Go and NVIDIA kernel-module producer outputs plus the reviewed,
   SHA-256-verified nvattest cache artifacts; and
5. only the mountpoints and symlinks required by the measured boot contract.

Package payloads are inert. No package maintainer scripts run while assembling
this archive. Documentation, administrative helpers and broad libraries remain
when they are part of a declared package payload; reducing them is separate,
evidence-driven TCB work.

NVIDIA `.deb` inputs use the same deterministic complete-payload normalizer as
`rules_distroless`. The flat NVIDIA repository is not resolved at build time:
its URLs and SHA-256 digests remain ordinary source locks. The normalizer does
not filter paths or execute package scripts.

The final `pkg_tar` receives package layers first and the measured overlay last.
This preserves ordinary additive filesystem semantics when a repository-owned
file intentionally replaces a package default, such as the Fabric Manager
command-socket setting.

The measured overlay also owns `/usr/lib/os-release` and the fixed files that
make mkosi's unavoidable systemd finalization byte-neutral: an empty
`/etc/.pwd.lock`, an empty `/usr/lib/clock-epoch`, and a `disable *` systemd
preset. Final disk assembly therefore adds no service enablement or other
runtime policy; only the ext4 formatter's `lost+found` directory is outside the
rootfs tar.

The rootfs target deliberately has no hostile-builder verifier, every-path
manifest, forbidden-path policy, package filter or runtime-footprint denylist.
The trusted release worker, independent reproduction, protected expected-
measurement promotion and runtime attestation are the integrity boundary.

`make shipping-image` passes this tar to mkosi as its only base tree. The
shipping step does not install packages, run package scripts, copy a builder
filesystem, or add a second rootfs overlay.
