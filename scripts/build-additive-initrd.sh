#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_dir="${TINFOIL_BUILDER_OUTPUT:-$repo_dir/build/builder-work/output}"
binary="$artifact_dir/artifacts/tinfoil-initrd"
raw_archive="${TINFOIL_INITRD_RAW:-$repo_dir/build/artifacts/initrd.cpio}"
output="${TINFOIL_INITRD_OUTPUT:-$repo_dir/initrd.cpio.zst}"
manifest="$repo_dir/image/initrd/manifest.tsv"
tool="$repo_dir/scripts/initrd_manifest.py"
expected_zstd_version="1.5.7"

umask 022

actual_zstd_version="$(zstd --version | sed -n 's/.* v\([0-9][0-9.]*\),.*/\1/p')"
if [[ "$actual_zstd_version" != "$expected_zstd_version" ]]; then
    printf 'additive initrd: zstd version %s does not match pinned %s\n' \
        "${actual_zstd_version:-unknown}" "$expected_zstd_version" >&2
    exit 1
fi

"$tool" archive \
    --manifest "$manifest" \
    --binary "$binary" \
    --output "$raw_archive"

"$tool" compress \
    --input "$raw_archive" \
    --output "$output"

"$tool" verify-archive \
    --manifest "$manifest" \
    --binary "$binary" \
    --archive "$output"

printf 'additive initrd: %s  %s\n' "$(sha256sum "$output" | awk '{print $1}')" "$output"
