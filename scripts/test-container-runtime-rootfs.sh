#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 /path/to/container-runtime-rootfs-layer.tar /path/to/containerd-config.toml" >&2
    exit 2
fi

archive="$1"
containerd_config="$2"
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

config_path="etc/containerd/config.toml"
if [[ "$(grep -Fxc "$config_path" "$members")" -ne 1 ]]; then
    echo "$config_path must appear exactly once in the packaged rootfs layer" >&2
    exit 1
fi
config_metadata="$(tar --numeric-owner -tvf "$archive" "$config_path" | awk '{print $1, $2}')"
if [[ "$config_metadata" != "-rw-r--r-- 0/0" ]]; then
    echo "$config_path metadata must be mode 0644 and owner 0:0" >&2
    exit 1
fi
tar -xf "$archive" -C "$scratch" "$config_path"
if [[ ! -f "$scratch/$config_path" || -L "$scratch/$config_path" ]]; then
    echo "$config_path must be a regular file" >&2
    exit 1
fi
if ! cmp -s "$containerd_config" "$scratch/$config_path"; then
    echo "$config_path differs from the measured source configuration" >&2
    exit 1
fi

expected_config_digest="b2f8b797ab9c0f0b520c8a1e7ac022fe0b607e08562c70fa49ff5888d6c5485d"
actual_config_digest="$(sha256sum "$scratch/$config_path" | cut -d' ' -f1)"
if [[ "$actual_config_digest" != "$expected_config_digest" ]]; then
    echo "$config_path digest mismatch" >&2
    exit 1
fi

if grep -Eq '^opt/containerd/image-verifier(/|$)' "$members"; then
    echo "external containerd image verifiers must not be packaged" >&2
    exit 1
fi
