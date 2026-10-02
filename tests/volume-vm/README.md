# Volume regression tests

Checks locked-write rejection, writable unlock propagation, persistence across
VM restarts, and unchanged disk contents after rejected keys or reinitialization.
Run commands from the repository root.

## Encrypted volume lifecycle

Requires Docker BuildKit with Linux/AMD64 build support. The runner uses QEMU
software emulation and a temporary 256 MiB disk; no host devices are attached.

```sh
docker build -f tests/volume-vm/Dockerfile -t cvmimage-volume-vm:guard .
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=1g --memory 2g --cpus 2 \
  cvmimage-volume-vm:guard
```

Both initialize and reopen boots must pass. Exit 77 means a missing prerequisite,
not success. This fixture tests volume behavior, not hardware attestation.

## Mount propagation

Uses an isolated Linux mount namespace and tmpfs, without block devices. Tests
read-only placeholders, inherited mount flags, writable unlock, and rollback.

```sh
docker run --rm --cap-drop ALL --cap-add SYS_ADMIN --cap-add DAC_OVERRIDE \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  -e TINFOIL_VOLUME_MOUNT_TEST=1 -w /src/tinfoil golang:1.26-alpine \
  go test -v -count=3 -timeout=60s ./internal/volume
```

## Unit tests

```sh
docker build --target guest -f tests/volume-vm/Dockerfile \
  -t cvmimage-volume-tests:guard .
docker run --rm --platform linux/amd64 --network none --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  -e CGO_ENABLED=1 -w /src/tinfoil cvmimage-volume-tests:guard \
  sh -c 'go test -count=1 ./internal/volume ./cmd/boot ./cmd/pid1 ./cmd/volumeworker &&
    go vet ./internal/volume ./cmd/boot ./cmd/pid1 ./cmd/volumeworker'
```

Ordinary unit runs skip the opt-in mount and VM tests; run those separately above.
