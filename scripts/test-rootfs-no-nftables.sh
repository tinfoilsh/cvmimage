#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/rootfs.tar" >&2
    exit 2
fi

members="$(mktemp)"
trap 'rm -f "$members"' EXIT
tar -tf "$1" >"$members"

for path in \
    usr/sbin/nft usr/bin/nft sbin/nft bin/nft \
    etc/nftables.conf usr/lib/systemd/system/nftables.service \
    usr/share/man/man8/nft.8.gz; do
    if grep -Eq "^(\\./)?${path}$" "$members"; then
        echo "$path must not be present in the runtime rootfs" >&2
        exit 1
    fi
done

for prefix in \
    usr/share/doc/nftables usr/share/doc/libnftables1 \
    usr/share/doc/libnftnl11 usr/share/nftables; do
    if grep -Eq "^(\\./)?${prefix}(/|$)" "$members"; then
        echo "$prefix proves the nftables package payload is present" >&2
        exit 1
    fi
done

for library in libnftables libnftnl; do
    if grep -Eq "^(\\./)?usr/lib/[^/]+/${library}\\.so(\\.|$)" "$members"; then
        echo "$library must not be present in the runtime rootfs" >&2
        exit 1
    fi
done
