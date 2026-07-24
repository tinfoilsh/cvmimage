#!/bin/bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 /path/to/runtime-packages.lock.json PACKAGE_LAYER..." >&2
    exit 2
fi

lock="$1"
shift

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

grep -Fq '"key": "libcap2-bin_1-2.75-10ubuntu2_amd64"' "$lock"
grep -Fq '"sha256": "d92a8f9affbd2277d191e65978ba2a194d00d00a04f52ee9d1bca2a2ba26697d"' "$lock"

members="$scratch/members"
: >"$members"
for archive in "$@"; do
    tar -tzf "$archive" | sed 's#^\./##' >>"$members"
done

forbidden=(
    usr/sbin/capsh
    usr/sbin/getcap
    usr/sbin/getpcaps
    usr/sbin/setcap
    usr/share/doc/libcap2-bin/README.Debian
    usr/share/doc/libcap2-bin/changelog.Debian.gz
    usr/share/doc/libcap2-bin/copyright
    usr/share/lintian/overrides/libcap2-bin
    usr/share/man/man1/capsh.1.gz
    usr/share/man/man8/getcap.8.gz
    usr/share/man/man8/getpcaps.8.gz
    usr/share/man/man8/setcap.8.gz
)
for path in "${forbidden[@]}"; do
    if grep -Fqx "$path" "$members"; then
        echo "$path must not be present in the measured runtime package layers" >&2
        exit 1
    fi
done

required=(
    usr/bin/ip
    usr/lib/x86_64-linux-gnu/libcap.so.2
    usr/lib/x86_64-linux-gnu/libcap.so.2.75
    usr/sbin/ip
)
for path in "${required[@]}"; do
    if [[ "$(grep -Fxc "$path" "$members")" -ne 1 ]]; then
        echo "$path must appear exactly once in the measured runtime package layers" >&2
        exit 1
    fi
done

ip_archive=""
libcap_archive=""
for archive in "$@"; do
    archive_members="$scratch/archive-members"
    tar -tzf "$archive" | sed 's#^\./##' >"$archive_members"
    if grep -Fqx 'usr/bin/ip' "$archive_members"; then
        ip_archive="$archive"
    fi
    if grep -Fqx 'usr/lib/x86_64-linux-gnu/libcap.so.2.75' "$archive_members"; then
        libcap_archive="$archive"
    fi
done

if [[ -z "$ip_archive" || -z "$libcap_archive" ]]; then
    echo "required iproute2 or libcap2 package layer was not selected" >&2
    exit 1
fi

tar -xzf "$ip_archive" -C "$scratch" ./usr/bin/ip ./usr/sbin/ip
tar -xzf "$libcap_archive" -C "$scratch" \
    ./usr/lib/x86_64-linux-gnu/libcap.so.2 \
    ./usr/lib/x86_64-linux-gnu/libcap.so.2.75

if [[ ! -f "$scratch/usr/bin/ip" || -L "$scratch/usr/bin/ip" || ! -x "$scratch/usr/bin/ip" ]]; then
    echo "usr/bin/ip must be an executable regular file" >&2
    exit 1
fi
if [[ "$(readlink "$scratch/usr/sbin/ip")" != "../bin/ip" ]]; then
    echo "usr/sbin/ip must remain the fixed ../bin/ip symlink" >&2
    exit 1
fi
if [[ "$(readlink "$scratch/usr/lib/x86_64-linux-gnu/libcap.so.2")" != "libcap.so.2.75" ]]; then
    echo "libcap.so.2 must remain the fixed libcap.so.2.75 symlink" >&2
    exit 1
fi
if ! readelf -dW "$scratch/usr/bin/ip" | grep -Fq 'Shared library: [libcap.so.2]'; then
    echo "usr/bin/ip must retain its libcap.so.2 dependency" >&2
    exit 1
fi
