# Deterministic NVIDIA module producer

`kernel/build-nvidia-open-local.sh` builds the three external modules required
by the measured guest:

- `nvidia.ko`
- `nvidia-uvm.ko`
- `nvidia-modeset.ko`

The producer pins the NVIDIA source packages and host toolchain versions, uses
the pinned custom Linux 7.0 source tree, fixes the kernel build environment,
and builds serially. Before publishing the three named files, it checks each
module's vermagic and selected symbol CRCs against the custom kernel.

The producer runs in the shared pinned disposable runtime builder. Package
installation and maintainer scripts are permitted in that builder because its
filesystem is never a runtime or measured-image input. Of the shared producer
entrypoints, only NVIDIA receives `CAP_SYS_ADMIN`; it is used for the fixed
mount namespace and bind mounts required by the canonical module build, without
exposing host devices to the container.

By default, the modules are written beneath
`kernel/out/rootfs-artifacts/nvidia-modules`. A later rootfs assembly step is
responsible for installing them at `/usr/lib/tinfoil/kernel-modules`.
The checked-in Bazel package in that output directory exposes the fixed
`//kernel/out/rootfs-artifacts/nvidia-modules:modules` filegroup consumed by
rootfs assembly. The producer writes only the three module files.
Downloaded source packages are retained in `kernel/build/nvidia-packages` and
are verified against the pinned hashes before every build.

The publication contract consists only of the three fixed module names above.
Temporary source trees, package state, compiler caches, logs, and all other
builder filesystem contents are discarded and are not eligible rootfs inputs.

The normal producer command is:

```sh
./scripts/build-runtime-builder.sh
./scripts/run-runtime-builder.sh nvidia
```

Full reproduction is intentionally release-only because it performs two
complete isolated kernel and NVIDIA builds. It does not run in routine PR CI:

```sh
./scripts/reproduce-nvidia-modules.sh
```

The pinned kernel source package is verified and stored inside the disposable
builder image. NVIDIA source packages are downloaded into each isolated build
cache and verified against their committed SHA-256 values before use.

The comparison succeeds only when all three module files are byte-identical.
It does not publish artifacts or authenticate a builder.

Build-time denial of service is accepted. A failed or malicious builder can
delay a release, but only byte-identical named outputs from the pinned release
process can contribute to the promoted image measurement.
