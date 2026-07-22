#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

hash_a=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
hash_b=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210

run_hash() {
    make --no-print-directory -s -C "$workdir" -f "$repo_root/Makefile" hash
}

expect_failure() {
    if run_hash >/dev/null 2>&1; then
        echo "$1 unexpectedly succeeded" >&2
        exit 1
    fi
}

expect_failure "missing roothash"

printf '%s' "$hash_a" > "$workdir/tinfoilcvm.roothash"
if output=$(run_hash) && [ "$output" = "$hash_a" ]; then
    :
else
    echo "authoritative roothash was not returned" >&2
    exit 1
fi

printf 'invalid' > "$workdir/tinfoilcvm.roothash"
expect_failure "malformed roothash"

printf '%s' "$hash_a" > "$workdir/tinfoilcvm.roothash"
printf '%s' "$hash_a" > "$workdir/tinfoilcvm.hash"
if output=$(run_hash) && [ "$output" = "$hash_a" ]; then
    :
else
    echo "matching compatibility artifact was rejected" >&2
    exit 1
fi

printf 'invalid' > "$workdir/tinfoilcvm.hash"
expect_failure "malformed compatibility hash"

printf '%s' "$hash_b" > "$workdir/tinfoilcvm.hash"
expect_failure "stale compatibility hash"

rm "$workdir/tinfoilcvm.roothash"
expect_failure "compatibility-only hash"
