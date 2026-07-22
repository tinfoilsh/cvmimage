#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$repo_dir/build/reproducibility"
evidence="$repo_dir/evidence/additive-initrd-reproducibility.txt"
trusted_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

source_status="$(git -C "$repo_dir" status --porcelain=v1 --untracked-files=all --ignored=matching -- tinfoil)"
if [ -n "$source_status" ]; then
    printf 'reproducibility check: refusing uncommitted or ignored tinfoil source:\n%s\n' \
        "$source_status" >&2
    exit 1
fi
source_revision="tinfoil-tree:$(git -C "$repo_dir" rev-parse HEAD:tinfoil)"

cleanup() {
    sudo env PATH="$trusted_path" rm -rf "$scratch"
}
trap cleanup EXIT

sudo env PATH="$trusted_path" rm -rf "$scratch"
mkdir -p "$scratch" "$(dirname "$evidence")"

mkosi_version="$(sudo env PATH="$trusted_path" mkosi --version)"
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
    if ! sudo env PATH="$trusted_path" mkosi -C "$repo_dir/builder" \
        --environment=TINFOIL_SOURCE_REVISION="$source_revision" \
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

    sudo env PATH="$trusted_path" \
        TINFOIL_BUILDER_OUTPUT="$root/builder-work/output" \
        TINFOIL_INITRD_STAGE="$root/stage" \
        TINFOIL_INITRD_RAW="$root/initrd.cpio" \
        TINFOIL_INITRD_OUTPUT="$root/initrd.cpio.zst" \
        "$repo_dir/scripts/build-additive-initrd.sh" >>"$log" 2>&1

    (cd "$root/builder-work/output" && sha256sum artifacts/*) > "$root/builder.sha256"
    sha256sum "$root/initrd.cpio.zst" > "$root/initrd.sha256"
}

build_once a
build_once b

builder_a="$(sha256sum "$scratch/a/builder.sha256" | cut -d' ' -f1)"
builder_b="$(sha256sum "$scratch/b/builder.sha256" | cut -d' ' -f1)"
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
for path in artifacts.tsv rootfs-artifacts.tsv \
    artifacts/tinfoil-initrd artifacts/tinfoil-init artifacts/tinfoil-boot \
    artifacts/tinfoil-container-status artifacts/tinfoil-egress artifacts/tinfoil-shim; do
    cmp "$scratch/a/builder-work/output/$path" "$scratch/b/builder-work/output/$path"
done
if ! cmp -s "$scratch/a/initrd.cpio.zst" "$scratch/b/initrd.cpio.zst"; then
    echo "initrd hashes match but archives are not byte-identical" >&2
    exit 1
fi

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
