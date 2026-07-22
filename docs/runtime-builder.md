# Shared runtime builder

The initrd Go binary, nvattest, custom kernel, and NVIDIA modules use one
disposable builder image. Its Ubuntu base digest, dated package snapshot, and
tool versions are pinned. Each producer has a fixed entrypoint and publishes
only explicitly named output files.

The builder is not a runtime filesystem source. Distribution packages and
their maintainer scripts may run inside it, and its package database, temporary
trees, caches, logs, and installed tools are discarded. Rootfs construction
may consume only the named producer outputs mounted from explicit output
directories.

The standard interface is:

```sh
./scripts/build-runtime-builder.sh
./scripts/run-runtime-builder.sh initrd
./scripts/run-runtime-builder.sh nvattest
./scripts/run-runtime-builder.sh kernel
./scripts/run-runtime-builder.sh nvidia
```

Initrd, nvattest, and kernel producers use ordinary unprivileged containers.
NVIDIA alone receives `CAP_SYS_ADMIN` with confined host-device access for its
fixed mount-namespace build. Output and cache paths are explicit; arbitrary
host environment state is not forwarded.

The build pipeline does not claim to defend against a malicious builder.
Build-time disruption and denial of service are accepted because they cannot
make an unapproved image pass runtime attestation. Release qualification, run
outside routine PR CI, performs clean repeated builds and compares the fixed
named outputs before promoting the resulting image measurement.
