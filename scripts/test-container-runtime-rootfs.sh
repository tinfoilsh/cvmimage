#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/docker-static-rootfs-layer.tar" >&2
    exit 2
fi

archive="$1"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

required=(
    containerd
    containerd-shim-runc-v2
    dockerd
    runc
)
forbidden=(
    ctr
    docker
    docker-init
    docker-proxy
)

members="$scratch/members"
tar -tf "$archive" >"$members"

for executable in "${required[@]}"; do
    path="usr/bin/$executable"
    if [[ "$(grep -Fxc "$path" "$members")" -ne 1 ]]; then
        echo "$path must appear exactly once in the packaged rootfs layer" >&2
        exit 1
    fi
    tar -xf "$archive" -C "$scratch" "$path"
    if [[ ! -f "$scratch/$path" || -L "$scratch/$path" || ! -x "$scratch/$path" ]]; then
        echo "$path must be an executable regular file" >&2
        exit 1
    fi
done

for executable in "${forbidden[@]}"; do
    path="usr/bin/$executable"
    if grep -Fqx "$path" "$members"; then
        echo "$path must not be present in the packaged rootfs layer" >&2
        exit 1
    fi
done
