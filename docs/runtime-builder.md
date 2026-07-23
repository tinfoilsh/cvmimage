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

Normal rootfs and image builds do not rebuild nvattest. They consume the two
fixed runtime artifacts from the durable local cache at
`${XDG_CACHE_HOME:-$HOME/.cache}/cvmimage-hardening/nvattest` by default,
overrideable with `NVATTEST_CACHE=/path`. The cache is shared across worktrees,
survives repository `clean` and `deepclean`, and is addressed by the reviewed
SHA-256 digests of the two runtime files. Consumers verify both digests and the
fixed ELF/runtime contract and fail closed when either artifact is absent or
mismatched. The epoch-zero staged copies are not Make targets, so their
reproducible timestamps cannot make the source producer appear perpetually
stale.

The standard producer interface is:

```sh
./scripts/build-runtime-builder.sh
./scripts/run-runtime-builder.sh initrd
./scripts/run-runtime-builder.sh kernel
./scripts/run-runtime-builder.sh nvidia
make test-go-producer
```

Regenerate and publish the fixed nvattest cache only when intentionally updating
or restoring it:

```sh
make regenerate-nvattest
```

The regeneration target builds from source in the pinned builder and refuses to
publish outputs unless they match the reviewed producer hashes. Changing those
hashes is a source update requiring review. `make reproducible-nvattest` performs
two isolated source builds and byte comparisons only during release
qualification; it is not a dependency of normal images or routine PR CI.

Fresh release runners prime the durable cache explicitly with:

```sh
make release-nvattest-cache
```

That release-only target performs the required two isolated source builds,
compares them byte-for-byte, verifies the reviewed hashes, and publishes the
verified result into the local cache that `make shipping-image` then consumes.

Initrd, nvattest, and kernel producers use ordinary unprivileged containers.
NVIDIA alone receives `CAP_SYS_ADMIN` with confined host-device access for its
fixed mount-namespace build. Output and cache paths are explicit; arbitrary
host environment state is not forwarded.

The build pipeline does not claim to defend against a malicious builder.
Build-time disruption and denial of service are accepted because they cannot
make an unapproved image pass runtime attestation. Release qualification, run
outside routine PR CI, performs clean repeated builds and compares the fixed
named outputs before promoting the resulting image measurement.
