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

python3 - "$lock" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as lock_file:
    packages = json.load(lock_file)["packages"]

matches = [
    package
    for package in packages
    if package.get("key") == "debconf_1.5.92_amd64"
    and package.get("sha256") == "025984be5dc70b32e02c8a668fdcceba674173bbda4a3e7ff93fac800dcdd122"
]
if len(matches) != 1:
    raise SystemExit("locked debconf key and SHA-256 must identify exactly one package record")
PY

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

debconf_payload_members="$scratch/debconf-payload-members"
runtime_payload_members="$scratch/runtime-payload-members"
find "$scratch/debconf" \( -type f -o -type l \) -printf '%P\n' | LC_ALL=C sort -u >"$debconf_payload_members"
LC_ALL=C sort -u "$runtime_members" >"$runtime_payload_members"
overlap="$scratch/debconf-runtime-overlap"
comm -12 "$debconf_payload_members" "$runtime_payload_members" >"$overlap"
if [[ -s "$overlap" ]]; then
    echo "locked debconf payload members must not enter the measured runtime package layers:" >&2
    cat "$overlap" >&2
    exit 1
fi

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
