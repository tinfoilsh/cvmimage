#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$repo_dir/build/reproducibility"
evidence="$repo_dir/evidence/additive-initrd-reproducibility.txt"

cleanup() {
    sudo rm -rf "$scratch"
}
trap cleanup EXIT

sudo rm -rf "$scratch"
mkdir -p "$scratch" "$(dirname "$evidence")"

mkosi_version="$(mkosi --version)"
if [ "$mkosi_version" != "mkosi 26" ]; then
    printf 'reproducibility check requires mkosi 26, found: %s\n' \
        "${mkosi_version:-unknown}" >&2
    exit 1
fi

build_once() {
    local name="$1"
    local root="$scratch/$name"
    local log="$repo_dir/evidence/additive-initrd-builder-$name.log"

    mkdir -p "$root"
    if ! sudo env PATH="$PATH" mkosi -C "$repo_dir/builder" \
        --force \
        --incremental=no \
        --build-directory="$root/builder-work" \
        --cache-directory="$root/builder-cache" \
        --package-cache-directory="$root/builder-pkgcache" \
        --workspace-directory="$root/builder-workspace" \
        build >"$log" 2>&1; then
        tail -n 100 "$log" >&2
        return 1
    fi

    sudo env PATH="$PATH" \
        TINFOIL_BUILDER_OUTPUT="$root/builder-work/output" \
        TINFOIL_INITRD_STAGE="$root/stage" \
        TINFOIL_INITRD_RAW="$root/initrd.cpio" \
        TINFOIL_INITRD_OUTPUT="$root/initrd.cpio.zst" \
        "$repo_dir/scripts/build-additive-initrd.sh" >>"$log" 2>&1

    sha256sum "$root/builder-work/output/artifacts/tinfoil-initrd" > "$root/builder.sha256"
    sha256sum "$root/initrd.cpio.zst" > "$root/initrd.sha256"
}

build_once a
build_once b

builder_a="$(cut -d' ' -f1 "$scratch/a/builder.sha256")"
builder_b="$(cut -d' ' -f1 "$scratch/b/builder.sha256")"
initrd_a="$(cut -d' ' -f1 "$scratch/a/initrd.sha256")"
initrd_b="$(cut -d' ' -f1 "$scratch/b/initrd.sha256")"

if [ "$builder_a" != "$builder_b" ]; then
    echo "builder artifacts differ: $builder_a != $builder_b" >&2
    exit 1
fi
if [ "$initrd_a" != "$initrd_b" ]; then
    echo "initrd hashes differ: $initrd_a != $initrd_b" >&2
    cmp -l "$scratch/a/initrd.cpio.zst" "$scratch/b/initrd.cpio.zst" | head -n 100 >&2 || true
    exit 1
fi
cmp -s "$scratch/a/builder-work/output/artifacts/tinfoil-initrd" "$scratch/b/builder-work/output/artifacts/tinfoil-initrd"
cmp -s "$scratch/a/initrd.cpio.zst" "$scratch/b/initrd.cpio.zst"

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
