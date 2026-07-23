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
    echo "debug builder: non-canonical Go toolchain" >&2
    exit 1
fi
if [ "$(dpkg-query -W -f='${Version}' gcc)" != 4:15.2.0-5ubuntu1 ] ||
    [ "$(dpkg-query -W -f='${Version}' binutils)" != 2.46-3ubuntu2 ]; then
    echo "debug builder: non-canonical external Go linker toolchain" >&2
    exit 1
fi

umask 022
export GOTOOLCHAIN=local
export SOURCE_DATE_EPOCH=0

rm -rf "$artifact_dir"
mkdir -p "$artifact_dir"
cd "$source_root/tinfoil"

CC="$gcc_bin" CGO_ENABLED=1 "$go_bin" build \
    -trimpath \
    -buildvcs=false \
    -mod=readonly \
    -tags=tinfoil_debug_image \
    -ldflags='-s -w -buildid= -linkmode=external -extld=/usr/bin/gcc -extldflags=-Wl,--build-id=none' \
    -o "$artifact_dir/tinfoil-init" \
    ./cmd/init
chmod 0755 "$artifact_dir/tinfoil-init"
touch -d @0 "$artifact_dir/tinfoil-init"
printf 'debug builder: tinfoil-init sha256=%s modules=built-in\n' \
    "$(sha256sum "$artifact_dir/tinfoil-init" | awk '{print $1}')"
