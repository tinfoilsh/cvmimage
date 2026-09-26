# Isolated volume regression fixture

Run from the repository root. Docker BuildKit and support for building
Linux/AMD64 images are required (Docker Desktop provides this on Apple Silicon).
The guest architecture is deliberately AMD64 to match the measured PCI disk
contract. QEMU runs natively on the Docker host using software TCG, not KVM.

```sh
docker build -f tests/volume-vm/Dockerfile -t cvmimage-volume-vm:guard .
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=1g --memory 2g --cpus 2 \
  cvmimage-volume-vm:guard
```

The build downloads public Go modules and Alpine packages. No credentials are
copied or forwarded. The runner uses UID 65534, a fresh 256 MiB scratch image,
and a new QEMU process for each boot. It exposes no network, host paths, raw
devices, Docker socket, or hardware accelerator to the VM. There is deliberately
no `TEST_DEVICE` option. The scratch directory is removed on exit.

The fixture calls the real volume and device-mapper code, including the real
formatter subprocess, authenticated encryption, and the production PCI/serial
lookup. It checks:

- Locked writes return `EROFS` in a separate application-like mount namespace.
  The same root process retains `DAC_OVERRIDE` but not `SYS_ADMIN`.
- Unlocking a blank disk without `initialize` fails without changing its hash.
- Explicit initialization replies `ok`; the encrypted mount propagates writable
  into the same `rslave` application bind. The app writes and fsyncs a payload.
- Preparing an unlocked volume preserves its mount ID and writability.
- Unmounting returns the live application bind to its read-only placeholder.
- A second VM boot rejects reinitialization and wrong keys through both runtime
  unlock and boot `Mount`, leaving the entire raw disk SHA-256 unchanged.
- `Mount` with the original key recovers the original payload after VM restart.
- Three existing x86 seccomp test groups run on the guest kernel rather than
  relying on Docker's cross-architecture syscall emulation.

Exit **77** means QEMU or a required kernel module is unavailable, not success.
Other setup, assertion, and timeout failures return nonzero. Success requires
both the Go test pass marker and the guest's explicit success result for each
boot. Normal `go test` skips the opt-in VM and namespace tests; those skips do
not establish the kernel behavior.

## Device-free mount proof

This uses a new Linux mount namespace and bounded tmpfs only. No device-mapper
or block device access is granted. It also checks retained `nodev`, `nosuid`,
`noexec`, and `nosymfollow` flags, all three access-time modes with and without
`nodiratime`, idempotent placeholder preparation, and an unaffected parent
filesystem. Symlink traversal must fail with `ELOOP` before and after preparation
and after rollback; the complete statfs flag set must differ only by `ST_RDONLY`.

```sh
docker run --rm --cap-drop ALL --cap-add SYS_ADMIN --cap-add DAC_OVERRIDE \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  -e TINFOIL_VOLUME_MOUNT_TEST=1 -w /src/tinfoil golang:1.26-alpine \
  go test -v -count=3 -timeout=60s ./internal/volume
```

An explicitly requested namespace test fails if Linux capabilities or namespace
creation are denied. Do not reinterpret that failure as a passing mount proof.

## Go suite

The guest build stage includes the Go toolchain and C compiler required by the
current NVML source; no production source files or build constraints are changed.

```sh
docker build --target guest -f tests/volume-vm/Dockerfile \
  -t cvmimage-volume-tests:guard .
docker run --rm --platform linux/amd64 --network none --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  -e CGO_ENABLED=1 -w /src/tinfoil cvmimage-volume-tests:guard \
  sh -c 'go test -count=1 ./... && go vet ./...'
```

The focused unit tests can also run as nobody, with no Linux capabilities and
an executable scratch tmpfs for Go's temporary test binaries:

```sh
docker run --rm --platform linux/amd64 --user 65534:65534 --network none \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=512m \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  -e HOME=/tmp -e GOCACHE=/tmp/go-build -e CGO_ENABLED=1 -w /src/tinfoil \
  cvmimage-volume-tests:guard \
  go test -count=1 ./internal/volume ./cmd/boot ./cmd/volumeworker
```

On Apple Silicon, Docker's AMD64 syscall emulation rejects the existing x86
seccomp filters with `EINVAL` on both the base and patched source. On that
platform, run the remaining suite and targeted race checks as follows; the
three excluded groups are run, not skipped, by the QEMU fixture above:

```sh
docker run --rm --platform linux/amd64 --network none --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  -e CGO_ENABLED=1 -w /src/tinfoil cvmimage-volume-tests:guard sh -c '
    go test -count=1 -skip "^Test(ShimInheritedUnixListener|ServiceSocketDomains|ServiceDangerousSyscalls)$" ./... &&
    go vet ./... &&
    go test -race -count=1 ./internal/volume ./cmd/boot ./cmd/pid1 ./internal/containers ./internal/devicemapper &&
    go test -tags=tinfoil_debug_image ./cmd/pid1
  '
```

## Baseline comparison

The following overlays only the production volume file from the immutable
reference `35d94c85ad20e9f98cd4ddcf35dfe4574b5215fb` in a disposable build container.
The formatter, worker, and cryptographic code are unchanged by the guard. It
compiles the same VM assertions, omitting the unit/namespace tests of the new
private helper that does not exist in the reference.

```sh
git archive 35d94c85ad20e9f98cd4ddcf35dfe4574b5215fb tinfoil/internal/volume/volume.go |
  docker run --rm -i --platform linux/amd64 --network none --cap-drop ALL \
    --security-opt no-new-privileges \
    --mount type=volume,src=cvmimage-volume-baseline-fixture,dst=/out \
    -w /src/tinfoil cvmimage-volume-tests:guard sh -c '
      tar --no-same-owner -xf - -C /src &&
      CGO_ENABLED=0 go test -c -o /volume.test \
        ./internal/volume/volume.go ./internal/volume/worker.go ./internal/volume/format.go \
        ./internal/volume/app_integration_test.go ./internal/volume/vm_integration_test.go &&
      CGO_ENABLED=0 go build -o /tinfoil-volume-worker ./cmd/volumeworker &&
      sh /fixture/pack.sh && cp /boot/vmlinuz-lts /out/vmlinuz &&
      cp /fixture/initramfs.gz /fixture/run.sh /out/
    '
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=1g --memory 2g --cpus 2 \
  --mount type=volume,src=cvmimage-volume-baseline-fixture,dst=/fixture,readonly \
  cvmimage-volume-vm:guard
```

Expected reference result: exit 1 with `readonly=false EROFS=false` at all three
locked-write assertions (before key, after failed blank unlock, after unmount).
The successful initialization and writable encrypted-mount assertions still
run. Expected patched result: exit 0 across both VM boots.

## Recorded validation and scope

Validated on macOS/ARM64 Docker Desktop, Go 1.26.8, QEMU 10.1.5 TCG, and an
Alpine Linux 6.18.53 AMD64 guest. The baseline reproduced all three unsafe write
cases. The patched namespace proof passed three repetitions; encrypted
initialize/restart/reopen passed twice. In one run, the wrong-key/reinitialize
disk hash was unchanged at
`302a17809fd80fae5360d56e5c70724dfbd26693a36bd3ef53f4df3fdbd43824`.
The recovered payload SHA-256 was
`967659bf87142168d69fea7e3f0f7ced78355ae37c4539a76f03b508505c3d5d`.
Fresh disk hashes vary because formatting and authenticated writes use randomness.
The non-root unit run, vet, targeted race checks, and debug PID 1 tests passed.
The missing-QEMU branch was separately exercised and returned exit 77.

Review against the reference found only the intentional production deviation:
inspect the prepared mount, then bind-remount a locked placeholder read-only
while retaining its existing safety flags. Crypto parameters, HKDF inputs,
blank detection, formatting/rollback, runtime seal, worker lifecycle/status,
boot key-secret resolution, and container `rslave` binds are unchanged. Unit
tests cover inspection/mount errors and application-start failure gates.

This is an application-like bind proof, not a full Docker daemon or production
CVM boot. The fixture uses a distro kernel and no TDX/SNP hardware; it does not
validate hardware attestation or the complete measured guest image. It neither
disables nor replaces production attestation. A new guest release and approved
pin update are still required; this fixture does not publish either.

The [follow-up security review](REVIEW.md) records the inherited-flag regression,
its immutable baseline reproduction, the fixture corrections, and fresh validation.

References: Linux [`mount(2)`](https://man7.org/linux/man-pages/man2/mount.2.html),
[shared subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html), and
QEMU [direct Linux boot](https://www.qemu.org/docs/master/system/linuxboot.html).
