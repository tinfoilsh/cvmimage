#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 SOURCE_ROOT OUTPUT_ROOT" >&2
    exit 2
fi

source_root=$1
output_root=$2
artifact_dir="$output_root/artifacts"
go_bin=/usr/lib/go-1.25/bin/go
gcc_bin=/usr/bin/gcc

if [ ! -f "$source_root/tinfoil/go.mod" ]; then
    echo "missing tinfoil source tree: $source_root/tinfoil" >&2
    exit 1
fi
if [ "$("$go_bin" version | awk '{print $3}')" != go1.25.7 ]; then
    echo "builder: non-canonical Go toolchain" >&2
    exit 1
fi
if [ "$(dpkg-query -W -f='${Version}' gcc)" != 4:15.2.0-5ubuntu1 ] ||
    [ "$(dpkg-query -W -f='${Version}' binutils)" != 2.46-3ubuntu2 ]; then
    echo "builder: non-canonical external Go linker toolchain" >&2
    exit 1
fi

umask 022
export GOTOOLCHAIN=local
export SOURCE_DATE_EPOCH=0

rm -rf "$artifact_dir"
mkdir -p "$artifact_dir"

cd "$source_root/tinfoil"
finish_command() {
    local name=$1
    local binary="$artifact_dir/$name"

    chmod 0755 "$binary"
    touch -d @0 "$binary"

    printf 'builder: %s sha256=%s modules=built-in\n' \
        "$name" "$(sha256sum "$binary" | awk '{print $1}')"
}

build_runtime_command() {
    local name=$1
    local package=$2
    local binary="$artifact_dir/$name"

    CC="$gcc_bin" CGO_ENABLED=1 "$go_bin" build \
        -trimpath \
        -buildvcs=false \
        -mod=readonly \
        -ldflags='-s -w -buildid= -linkmode=external -extld=/usr/bin/gcc -extldflags=-Wl,--build-id=none' \
        -o "$binary" \
        "$package"

    finish_command "$name"
}

build_runtime_command tinfoil-boot ./cmd/boot
build_runtime_command tinfoil-container-status ./cmd/container-status
build_runtime_command tinfoil-egress ./cmd/egress
build_runtime_command tinfoil-init ./cmd/init
build_runtime_command tinfoil-shim ./cmd/shim
