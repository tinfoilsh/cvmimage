#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/rootfs.tar" >&2
    exit 2
fi

members="$(mktemp)"
trap 'rm -f "$members"' EXIT
tar -tf "$1" >"$members"

for path in usr/sbin/ip usr/bin/ip sbin/ip bin/ip; do
    if grep -Eq "^(\\./)?${path}$" "$members"; then
        echo "$path must not be present in the runtime rootfs" >&2
        exit 1
    fi
done

for prefix in usr/include/iproute2 usr/share/doc/iproute2 usr/share/iproute2; do
    if grep -Eq "^(\\./)?${prefix}(/|$)" "$members"; then
        echo "$prefix proves the iproute2 package payload is present" >&2
        exit 1
    fi
done
