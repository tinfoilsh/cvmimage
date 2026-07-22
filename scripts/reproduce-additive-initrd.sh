#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-additive-initrd-repro.XXXXXXXX")"
evidence="$repo_dir/evidence/additive-initrd-reproducibility.txt"
trap 'rm -rf -- "$scratch"' EXIT

mkdir -p "$repo_dir/evidence"
"$repo_dir/scripts/build-runtime-builder.sh"

build_once() {
    local name=$1
    local root="$scratch/$name"
    local log="$repo_dir/evidence/additive-initrd-builder-$name.log"

    mkdir -p "$root"
    TINFOIL_BUILDER_OUTPUT="$root/builder-output" \
        TINFOIL_RUNTIME_BUILDER_CACHE="$root/builder-cache" \
        "$repo_dir/scripts/run-runtime-builder.sh" initrd >"$log" 2>&1
    TINFOIL_BUILDER_OUTPUT="$root/builder-output" \
        TINFOIL_INITRD_RAW="$root/initrd.cpio" \
        TINFOIL_INITRD_OUTPUT="$root/initrd.cpio.zst" \
        "$repo_dir/scripts/build-additive-initrd.sh" >>"$log" 2>&1

    sha256sum "$root/builder-output/artifacts/tinfoil-initrd" > "$root/builder.sha256"
    sha256sum "$root/initrd.cpio.zst" > "$root/initrd.sha256"
}

build_once a
build_once b

builder_a="$(cut -d' ' -f1 "$scratch/a/builder.sha256")"
builder_b="$(cut -d' ' -f1 "$scratch/b/builder.sha256")"
initrd_a="$(cut -d' ' -f1 "$scratch/a/initrd.sha256")"
initrd_b="$(cut -d' ' -f1 "$scratch/b/initrd.sha256")"

cmp "$scratch/a/builder-output/artifacts/tinfoil-initrd" \
    "$scratch/b/builder-output/artifacts/tinfoil-initrd"
cmp "$scratch/a/initrd.cpio.zst" "$scratch/b/initrd.cpio.zst"

cat > "$evidence" <<EOF
builder_a_sha256=$builder_a
builder_b_sha256=$builder_b
initrd_a_sha256=$initrd_a
initrd_b_sha256=$initrd_b
builder_byte_identical=yes
initrd_byte_identical=yes
builder_a_log=$repo_dir/evidence/additive-initrd-builder-a.log
builder_b_log=$repo_dir/evidence/additive-initrd-builder-b.log
EOF

printf 'reproducible builder artifact: %s\n' "$builder_a"
printf 'reproducible additive initrd: %s\n' "$initrd_a"
