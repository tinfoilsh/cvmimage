#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 RELEASE_ROOTFS [DEBUG_LAYER]" >&2
    exit 2
fi

release_rootfs=$1
busybox_sha256=df12634c17fcdca839ae5dc47d7627b7558511f7645de7c99ccf097a0f28ed5b
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-debug-contract.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

test -s "$release_rootfs"

tar -tf "$release_rootfs" | sed 's#^\./##' > "$scratch/release-members"
shell_names=(sh bash dash ash zsh ksh mksh yash fish csh tcsh busybox toybox)
shell_dirs=(bin sbin usr/bin usr/sbin usr/local/bin usr/local/sbin)
for directory in "${shell_dirs[@]}"; do
    for shell_name in "${shell_names[@]}"; do
        if grep -Fqx "$directory/$shell_name" "$scratch/release-members"; then
            echo "shipping rootfs contains executable shell path $directory/$shell_name" >&2
            exit 1
        fi
    done
done

mkdir "$scratch/release"
tar -xf "$release_rootfs" -C "$scratch/release" usr/bin/tinfoil-init
strings "$scratch/release/usr/bin/tinfoil-init" > "$scratch/release-strings"
if grep -Eq '/dev/hvc0|/usr/bin/busybox|debug console|debug image' "$scratch/release-strings"; then
    echo 'release PID1 contains debug-console infrastructure' >&2
    exit 1
fi

if [ "$#" -eq 1 ]; then
    echo 'shipping image contract tests passed'
    exit 0
fi

debug_layer=$2
test -s "$debug_layer"
tar -tf "$debug_layer" | sed 's#^\./##' > "$scratch/debug-members"
if [ "$(grep -Fxc 'usr/bin/busybox' "$scratch/debug-members")" -ne 1 ]; then
    echo 'debug rootfs must contain exactly one pinned BusyBox' >&2
    exit 1
fi

mkdir "$scratch/debug"
tar -xf "$debug_layer" -C "$scratch/debug" usr/bin/tinfoil-init
tar -xf "$debug_layer" -C "$scratch/debug" ./usr/bin/busybox
printf '%s  %s\n' "$busybox_sha256" "$scratch/debug/usr/bin/busybox" | sha256sum -c --strict
if cmp -s "$scratch/release/usr/bin/tinfoil-init" "$scratch/debug/usr/bin/tinfoil-init"; then
    echo 'debug PID1 is byte-identical to release PID1' >&2
    exit 1
fi
strings "$scratch/debug/usr/bin/tinfoil-init" > "$scratch/debug-strings"
for marker in /dev/hvc0 /usr/bin/busybox tinfoil-debug-console; do
    if ! grep -Fq -- "$marker" "$scratch/debug-strings"; then
        echo "debug PID1 is missing $marker" >&2
        exit 1
    fi
done

echo 'debug image contract tests passed'
