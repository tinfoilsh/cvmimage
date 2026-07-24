# Shared runtime builder

The six measured Go commands, nvattest, custom kernel, and NVIDIA modules use
one disposable builder image. Its Ubuntu base digest, dated package snapshot,
and tool versions are pinned. Each producer has a fixed entrypoint and
publishes only explicitly named output files.

The Go producer emits exactly these files under `artifacts/`, with no command
discovery: `tinfoil-boot`, `tinfoil-container-status`, `tinfoil-egress`,
`tinfoil-init`, `tinfoil-initrd`, and `tinfoil-shim`. It uses the fixed Go
1.25.7 toolchain with `GOTOOLCHAIN=local`, read-only modules, trimmed paths,
omitted VCS metadata, and empty Go build IDs. `tinfoil-initrd` disables CGO and
is statically linked. The five measured runtime commands enable CGO and use
the pinned GCC/binutils toolchain in external-link mode with the ELF build ID
disabled.

The builder is not a runtime filesystem source. Distribution packages and
their maintainer scripts may run inside it, and its package database, temporary
trees, caches, logs, and installed tools are discarded. Rootfs construction
may consume only the named producer outputs mounted from explicit output
directories.

Normal rootfs and image builds never compile nvattest. They require the two
fixed worktree-local runtime outputs and fail with an instruction to run `make
regenerate-nvattest` when either is absent. The trusted builder publishes those
files directly; there is no second output-authentication or cache-lock layer.

The standard producer interface is:

```sh
./scripts/build-runtime-builder.sh
./scripts/run-runtime-builder.sh initrd
./scripts/run-runtime-builder.sh kernel
./scripts/run-runtime-builder.sh nvidia
```

Regenerate nvattest explicitly when changing its source or build inputs:

```sh
make regenerate-nvattest
```

The release workflow calls `make release-image`, which first regenerates
nvattest from pinned inputs on the fresh release worker and then builds the
shipping image. `make reproducible-nvattest` remains a release-qualification
tool and is not part of routine PR CI.

Initrd, nvattest, and kernel producers use ordinary unprivileged containers.
NVIDIA alone receives `CAP_SYS_ADMIN` with confined host-device access for its
fixed mount-namespace build. Output paths are explicit; arbitrary host
environment state is not forwarded.

The build pipeline does not claim to defend against a malicious builder.
Build-time disruption and denial of service are accepted because they cannot
make an unapproved image pass runtime attestation. Release qualification, run
outside routine PR CI, performs clean repeated builds and compares the fixed
named outputs before promoting the resulting image measurement.
