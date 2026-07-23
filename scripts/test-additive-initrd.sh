#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_dir/image/initrd/manifest.tsv"
tool="$repo_dir/scripts/initrd_manifest.py"
mkdir -p "$repo_dir/build"
scratch="$(mktemp -d "$repo_dir/build/additive-initrd-test.XXXXXX")"

cleanup() {
    rm -rf "$scratch"
}
trap cleanup EXIT

expect_failure() {
    local label="$1"
    shift
    if "$@" >"$scratch/failure.log" 2>&1; then
        echo "FAIL: accepted $label" >&2
        exit 1
    fi
    printf 'OK: rejected %s\n' "$label"
}

printf 'fixed test binary\n' > "$scratch/tinfoil-initrd"
chmod 0755 "$scratch/tinfoil-initrd"

for name in a b; do
    "$tool" archive \
        --manifest "$manifest" \
        --binary "$scratch/tinfoil-initrd" \
        --output "$scratch/initrd-$name.cpio"
    "$tool" compress \
        --input "$scratch/initrd-$name.cpio" \
        --output "$scratch/initrd-$name.cpio.zst"
    "$tool" verify-archive \
        --manifest "$manifest" \
        --binary "$scratch/tinfoil-initrd" \
        --archive "$scratch/initrd-$name.cpio.zst"
done

cmp "$scratch/initrd-a.cpio" "$scratch/initrd-b.cpio"
cmp "$scratch/initrd-a.cpio.zst" "$scratch/initrd-b.cpio.zst"

bad_manifest="$scratch/bad-manifest.tsv"
sed \
    -e 's#/usr/bin/tinfoil-initrd\tfile#/usr/bin/other\tfile#' \
    -e 's#\tusr/bin/tinfoil-initrd$#\tusr/bin/other#' \
    "$manifest" > "$bad_manifest"
expect_failure "a non-canonical binary destination" \
    "$tool" archive --manifest "$bad_manifest" --binary "$scratch/tinfoil-initrd" --output "$scratch/bad.cpio"
grep -Fq 'manifest must contain only the fixed /usr/bin/tinfoil-initrd file' \
    "$scratch/failure.log"

ln -s tinfoil-initrd "$scratch/interposed-binary"
expect_failure "a symlinked named binary" \
    "$tool" archive --manifest "$manifest" --binary "$scratch/interposed-binary" --output "$scratch/symlink.cpio"

cp "$scratch/initrd-a.cpio.zst" "$scratch/changed.cpio.zst"
printf x >> "$scratch/changed.cpio.zst"
expect_failure "a changed compressed archive" \
    "$tool" verify-archive --manifest "$manifest" --binary "$scratch/tinfoil-initrd" --archive "$scratch/changed.cpio.zst"

printf '%s\n' 'deterministic named additive initrd tests passed'
