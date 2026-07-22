#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_dir="${TINFOIL_BUILDER_OUTPUT:-$repo_dir/build/builder-work/output}"
stage_dir="${TINFOIL_INITRD_STAGE:-$repo_dir/build/stage/initrd}"
raw_archive="${TINFOIL_INITRD_RAW:-$repo_dir/build/artifacts/initrd.cpio}"
output="${TINFOIL_INITRD_OUTPUT:-$repo_dir/initrd.cpio.zst}"
manifest="$repo_dir/image/initrd/manifest.tsv"
artifacts="$artifact_dir/artifacts.tsv"
artifact_lock="$repo_dir/image/manifests/artifacts.lock.tsv"
tool="$repo_dir/scripts/initrd_manifest.py"
expected_zstd_version="1.5.7"

umask 022

actual_zstd_version="$(zstd --version | sed -n 's/.* v\([0-9][0-9.]*\),.*/\1/p')"
if [[ "$actual_zstd_version" != "$expected_zstd_version" ]]; then
    printf 'additive initrd: zstd version %s does not match pinned %s\n' \
        "${actual_zstd_version:-unknown}" "$expected_zstd_version" >&2
    exit 1
fi

locked_source_count="$(
    awk -F '\t' '$0 !~ /^#/ && $1 == "tinfoil-initrd" { count++ } END { print count + 0 }' "$artifact_lock"
)"
locked_source_revision="$(
    awk -F '\t' '$0 !~ /^#/ && $1 == "tinfoil-initrd" { print $3; exit }' "$artifact_lock"
)"
if [ "$locked_source_count" -ne 1 ]; then
    echo "additive initrd: lock must contain exactly one tinfoil-initrd source revision" >&2
    exit 1
fi
source_status="$(git -C "$repo_dir" status \
    --porcelain=v1 --untracked-files=all --ignored=matching -- tinfoil)"
if [ -n "$source_status" ]; then
    printf 'additive initrd: refusing uncommitted or ignored tinfoil source:\n%s\n' \
        "$source_status" >&2
    exit 1
fi
actual_source_revision="tinfoil-tree:$(git -C "$repo_dir" rev-parse HEAD:tinfoil)"
if [ "$locked_source_revision" != "$actual_source_revision" ]; then
    printf 'additive initrd: source lock mismatch: %s != %s\n' \
        "$locked_source_revision" "$actual_source_revision" >&2
    exit 1
fi

"$tool" stage \
    --manifest "$manifest" \
    --artifacts "$artifacts" \
    --artifact-lock "$artifact_lock" \
    --stage "$stage_dir"

"$tool" archive \
    --manifest "$manifest" \
    --artifacts "$artifacts" \
    --artifact-lock "$artifact_lock" \
    --stage "$stage_dir" \
    --output "$raw_archive"

mkdir -p "$(dirname "$output")"
rm -f -- "$output.tmp"
zstd -q -f -T1 -19 --no-progress "$raw_archive" -o "$output.tmp"
touch -d @0 "$output.tmp"
mv -f "$output.tmp" "$output"

"$tool" verify-archive \
    --manifest "$manifest" \
    --artifacts "$artifacts" \
    --artifact-lock "$artifact_lock" \
    --archive "$output"

printf 'additive initrd: %s  %s\n' "$(sha256sum "$output" | awk '{print $1}')" "$output"
