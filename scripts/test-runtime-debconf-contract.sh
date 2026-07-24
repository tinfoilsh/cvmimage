#!/bin/bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 /path/to/runtime-packages.lock.json /path/to/debconf-layer.tar.gz PACKAGE_LAYER..." >&2
    exit 2
fi

lock="$1"
debconf_archive="$2"
shift 2

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

grep -Fq '"key": "debconf_1.5.92_amd64"' "$lock"
grep -Fq '"sha256": "025984be5dc70b32e02c8a668fdcceba674173bbda4a3e7ff93fac800dcdd122"' "$lock"

debconf_members="$scratch/debconf-members"
tar -tzf "$debconf_archive" | sed 's#^\./##' >"$debconf_members"

debconf_paths=(
    etc/apt/apt.conf.d/70debconf
    etc/debconf.conf
    usr/bin/debconf
    usr/sbin/dpkg-preconfigure
    usr/sbin/dpkg-reconfigure
    usr/share/debconf/frontend
    usr/share/perl5/Debconf/Config.pm
)
for path in "${debconf_paths[@]}"; do
    if [[ "$(grep -Fxc "$path" "$debconf_members")" -ne 1 ]]; then
        echo "$path must appear exactly once in the locked debconf payload" >&2
        exit 1
    fi
done

mkdir "$scratch/debconf"
tar -xzf "$debconf_archive" -C "$scratch/debconf"

regular_files="$(find "$scratch/debconf" -type f | wc -l)"
symlinks="$(find "$scratch/debconf" -type l | wc -l)"
uncompressed_bytes="$(find "$scratch/debconf" -type f -printf '%s\n' | awk '{sum += $1} END {print sum + 0}')"
if [[ "$regular_files" -ne 134 || "$symlinks" -ne 1 || "$uncompressed_bytes" -ne 255330 ]]; then
    echo "locked debconf payload changed: expected 134 regular files, 1 symlink, and 255330 uncompressed file bytes; got $regular_files, $symlinks, and $uncompressed_bytes" >&2
    exit 1
fi

runtime_members="$scratch/runtime-members"
: >"$runtime_members"
for archive in "$@"; do
    if cmp -s "$debconf_archive" "$archive"; then
        echo "the locked debconf payload archive must not enter the measured runtime package layers" >&2
        exit 1
    fi
    tar -tzf "$archive" | sed 's#^\./##' >>"$runtime_members"
done

for path in "${debconf_paths[@]}"; do
    if grep -Fqx "$path" "$runtime_members"; then
        echo "$path must not be present in the measured runtime package layers" >&2
        exit 1
    fi
done

required=(
    usr/bin/ip
    usr/lib/x86_64-linux-gnu/libcap.so.2.75
)
for path in "${required[@]}"; do
    if [[ "$(grep -Fxc "$path" "$runtime_members")" -ne 1 ]]; then
        echo "$path must appear exactly once in the measured runtime package layers" >&2
        exit 1
    fi
done
