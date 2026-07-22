#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$(id -u)" -ne 0 ]; then
    exec sudo env PATH="$PATH" "$0" "$@"
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_dir/image/initrd/manifest.tsv"
artifacts="$repo_dir/build/builder-work/output/artifacts.tsv"
artifact_lock="$repo_dir/image/manifests/artifacts.lock.tsv"
tool="$repo_dir/scripts/initrd_manifest.py"
mkdir -p "$repo_dir/build"
scratch="$(mktemp -d "$repo_dir/build/additive-initrd-negative.XXXXXX")"
escape="/tmp/additive-initrd-escape-test-$$"

cleanup() {
    rm -rf "$scratch" "$escape"
}
trap cleanup EXIT

stage() {
    "$tool" stage --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" --stage "$scratch/stage"
}

verify() {
    "$tool" verify-stage --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" --stage "$scratch/stage"
}

expect_failure() {
    local label="$1"
    shift
    if "$@" >"$scratch/failure.log" 2>&1; then
        echo "FAIL: verifier accepted $label" >&2
        exit 1
    fi
    printf 'OK: verifier rejected %s\n' "$label"
}

escape_manifest="$scratch/escape.tsv"
escape_lock="$scratch/escape-lock.tsv"
sed "s#^/usr/bin/tinfoil-initrd\t#/$escape\t#" "$manifest" > "$escape_manifest"
sed "s#\t/usr/bin/tinfoil-initrd\$#\t/$escape#" "$artifact_lock" > "$escape_lock"
expect_failure "a double-slash staging escape" \
    "$tool" stage --manifest "$escape_manifest" --artifacts "$artifacts" --artifact-lock "$escape_lock" --stage "$scratch/escape-stage"
if [ -e "$escape" ]; then
    echo "FAIL: traversal test wrote outside its staging directory" >&2
    exit 1
fi

symlink_parent_manifest="$scratch/symlink-parent.tsv"
sed $'s#^/usr/bin\\tdir\\t0755\\t0\\t0\\t-\\tgenerated:runtime-binaries$#/usr/bin\\tsymlink\\t0777\\t0\\t0\\tbin-target\\ttest:symlink-parent#' \
    "$manifest" > "$symlink_parent_manifest"
printf '/usr/bin-target\tdir\t0755\t0\t0\t-\ttest:symlink-target\n' >> "$symlink_parent_manifest"
expect_failure "a file below a manifest symlink" \
    "$tool" stage --manifest "$symlink_parent_manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" --stage "$scratch/symlink-parent-stage"

module_manifest="$scratch/module.tsv"
module_lock="$scratch/module-lock.tsv"
sed -e $'s#^/usr/bin/tinfoil-initrd\\t#/usr/bin/payload.ko.zst\\t#' \
    -e $'s#\\tusr/bin/tinfoil-initrd\\t#\\tusr/bin/payload.ko.zst\\t#' \
    "$manifest" > "$module_manifest"
sed $'s#\\t/usr/bin/tinfoil-initrd$#\\t/usr/bin/payload.ko.zst#' \
    "$artifact_lock" > "$module_lock"
expect_failure "a kernel module payload path" \
    "$tool" stage --manifest "$module_manifest" --artifacts "$artifacts" --artifact-lock "$module_lock" --stage "$scratch/module-stage"

symlink_artifacts="$scratch/symlink-artifacts"
mkdir -p "$symlink_artifacts/artifacts"
cp "$artifacts" "$symlink_artifacts/artifacts.tsv"
ln -s "$(realpath "$(dirname "$artifacts")/artifacts/tinfoil-initrd")" \
    "$symlink_artifacts/artifacts/tinfoil-initrd"
expect_failure "an escaping artifact symlink" \
    "$tool" stage --manifest "$manifest" --artifacts "$symlink_artifacts/artifacts.tsv" --artifact-lock "$artifact_lock" --stage "$scratch/symlink-artifact-stage"

stage
archive_victim="$scratch/archive-victim"
printf sentinel > "$archive_victim"
ln -s "$archive_victim" "$scratch/archive-link"
expect_failure "a symlink archive output" \
    "$tool" archive --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --stage "$scratch/stage" --output "$scratch/archive-link"
if [ "$(cat "$archive_victim")" != sentinel ]; then
    echo "FAIL: archive output followed a symlink" >&2
    exit 1
fi

canonical_raw="$scratch/canonical.cpio"
noncanonical_archive="$scratch/noncanonical.cpio.zst"
"$tool" archive --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --stage "$scratch/stage" --output "$canonical_raw"
dd if=/dev/zero bs=512 count=1 status=none >> "$canonical_raw"
zstd -q -f -T1 -19 --no-progress "$canonical_raw" -o "$noncanonical_archive"
expect_failure "extra newc trailer padding" \
    "$tool" verify-archive --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --archive "$noncanonical_archive"

stage
mkdir "$scratch/stage/etc"
expect_failure "an undeclared path" verify

stage
rm "$scratch/stage/usr/bin/tinfoil-initrd"
expect_failure "a missing declared path" verify

stage
chmod 0700 "$scratch/stage/usr/bin/tinfoil-initrd"
expect_failure "a mode mismatch" verify

stage
printf x >> "$scratch/stage/usr/bin/tinfoil-initrd"
touch -d @0 "$scratch/stage/usr/bin/tinfoil-initrd"
expect_failure "a content hash mismatch" verify

stage
rm "$scratch/stage/init"
ln -s missing "$scratch/stage/init"
touch -h -d @0 "$scratch/stage/init"
expect_failure "a broken or changed symlink" verify

stage
chown 1:1 "$scratch/stage/usr/bin/tinfoil-initrd"
expect_failure "an ownership mismatch" verify

stage
touch "$scratch/stage/usr/bin/tinfoil-initrd"
expect_failure "a timestamp mismatch" verify

stage
mkfifo "$scratch/stage/unexpected-fifo"
expect_failure "a FIFO" verify

stage
if command -v setcap >/dev/null 2>&1; then
    setcap cap_sys_admin=ep "$scratch/stage/usr/bin/tinfoil-initrd"
    expect_failure "a file capability" verify
fi

dynamic="$scratch/dynamic"
cp -a "$(dirname "$artifacts")" "$dynamic"
cp /usr/bin/true "$dynamic/artifacts/tinfoil-initrd"
chmod 0755 "$dynamic/artifacts/tinfoil-initrd"
touch -d @0 "$dynamic/artifacts/tinfoil-initrd"
dynamic_hash="$(sha256sum "$dynamic/artifacts/tinfoil-initrd" | awk '{print $1}')"
sed -E "s#^(tinfoil-initrd\tartifacts/tinfoil-initrd\t)[a-f0-9]{64}#\\1$dynamic_hash#" "$artifacts" > "$dynamic/artifacts.tsv"
dynamic_lock="$dynamic/artifacts.lock.tsv"
sed -E "s#^(tinfoil-initrd\tsource-build\t[^\t]+\t[^\t]+\t)[a-f0-9]{64}#\\1$dynamic_hash#" "$artifact_lock" > "$dynamic_lock"
expect_failure "a dynamically linked entrypoint" \
    "$tool" stage --manifest "$manifest" --artifacts "$dynamic/artifacts.tsv" --artifact-lock "$dynamic_lock" --stage "$scratch/dynamic-stage"

setuid_manifest="$scratch/setuid.tsv"
sed 's#/usr/bin/tinfoil-initrd\tfile\t0755#/usr/bin/tinfoil-initrd\tfile\t4755#' "$manifest" > "$setuid_manifest"
expect_failure "a setuid manifest entry" \
    "$tool" stage --manifest "$setuid_manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" --stage "$scratch/setuid-stage"

extra_artifact_dir="$scratch/extra-artifacts"
cp -a "$(dirname "$artifacts")" "$extra_artifact_dir"
extra_artifacts="$extra_artifact_dir/artifacts.tsv"
cp "$artifacts" "$extra_artifacts"
printf 'unexpected\tartifacts/tinfoil-initrd\t%s\t0755\ttest:undeclared\n' \
    "$(sha256sum "$extra_artifact_dir/artifacts/tinfoil-initrd" | awk '{print $1}')" >> "$extra_artifacts"
expect_failure "an undeclared builder artifact" \
    "$tool" stage --manifest "$manifest" --artifacts "$extra_artifacts" --artifact-lock "$artifact_lock" --stage "$scratch/extra-artifact-stage"

printf '%s\n' 'module-free initrd policy passed'
printf '%s\n' 'additive initrd negative tests passed'
