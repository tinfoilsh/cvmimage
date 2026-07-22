#!/usr/bin/env bash
set -Eeuo pipefail

trusted_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [ "$(id -u)" -ne 0 ]; then
    exec sudo env PATH="$trusted_path" "$0" "$@"
fi
export PATH="$trusted_path"

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

python3 - "$tool" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("initrd_manifest", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.shutil.rmtree = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("rmtree called"))
for unsafe in (pathlib.Path("/tmp/.."), pathlib.Path("/etc")):
    try:
        module.create_stage(unsafe, {}, {})
    except ValueError as error:
        if "must be confined" not in str(error):
            raise
    else:
        raise SystemExit(f"unsafe staging path was accepted: {unsafe}")
PY
printf 'OK: verifier rejected staging paths outside the build tree\n'

python3 - "$tool" "$manifest" "$artifacts" "$artifact_lock" "$scratch" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("initrd_manifest", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
manifest = pathlib.Path(sys.argv[2])
artifact_manifest = pathlib.Path(sys.argv[3])
artifact_lock = pathlib.Path(sys.argv[4])
scratch = pathlib.Path(sys.argv[5])
entries = module.parse_manifest(manifest)
artifacts = module.parse_artifacts(artifact_manifest)
locks = module.parse_artifact_locks(artifact_lock)
module.verify_artifact_locks(entries, artifacts, locks)
visible = scratch / "swapped-stage"
retained = scratch / "retained-stage"

def swap_visible_root(root):
    if root != visible:
        raise AssertionError(f"unexpected root passed to test hook: {root}")
    root.rename(retained)
    root.mkdir()
    (root / "sentinel").write_text("replacement\n")

module._CREATE_STAGE_ROOT_OPENED_HOOK = swap_visible_root
module.create_stage(visible, entries, artifacts)
if sorted(path.name for path in visible.iterdir()) != ["sentinel"]:
    raise SystemExit("stage construction wrote through the swapped visible root")
if (visible / "sentinel").read_text() != "replacement\n":
    raise SystemExit("stage construction modified the replacement target")
module.verify_stage(retained, entries, artifacts)
PY
printf 'OK: retained stage descriptor resisted a visible-root swap\n'

unowned_stage="$scratch/unowned-stage"
mkdir "$unowned_stage"
printf sentinel > "$unowned_stage/sentinel"
expect_failure "an existing unowned staging directory" \
    "$tool" stage --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" --stage "$unowned_stage"
if [ "$(cat "$unowned_stage/sentinel")" != sentinel ]; then
    echo "FAIL: unowned staging directory was modified" >&2
    exit 1
fi

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

archive_parent_victim="$scratch/archive-parent-victim"
mkdir "$archive_parent_victim"
ln -s "$archive_parent_victim" "$scratch/archive-parent-link"
expect_failure "a symlinked archive output parent" \
    "$tool" archive --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --stage "$scratch/stage" --output "$scratch/archive-parent-link/archive.cpio"
if [ -e "$archive_parent_victim/archive.cpio" ]; then
    echo "FAIL: archive output followed a symlinked parent" >&2
    exit 1
fi

canonical_raw="$scratch/canonical.cpio"
noncanonical_archive="$scratch/noncanonical.cpio.zst"
"$tool" archive --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --stage "$scratch/stage" --output "$canonical_raw"
expect_failure "a symlinked compressed output parent" \
    "$tool" compress --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --input "$canonical_raw" --output "$scratch/archive-parent-link/archive.cpio.zst"
if [ -e "$archive_parent_victim/archive.cpio.zst" ]; then
    echo "FAIL: compressed output followed a symlinked parent" >&2
    exit 1
fi
dd if=/dev/zero bs=512 count=1 status=none >> "$canonical_raw"
zstd -q -f -T1 -19 --no-progress "$canonical_raw" -o "$noncanonical_archive"
expect_failure "extra newc trailer padding" \
    "$tool" verify-archive --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --archive "$noncanonical_archive"

uppercase_raw="$scratch/uppercase.cpio"
uppercase_archive="$scratch/uppercase.cpio.zst"
cp "$scratch/canonical.cpio" "$uppercase_raw"
python3 - "$uppercase_raw" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
for index in range(6, 110):
    if data[index] in b"abcdef":
        data[index] = ord(chr(data[index]).upper())
        break
else:
    raise SystemExit("canonical header had no lowercase hex digit to mutate")
path.write_bytes(data)
PY
zstd -q -f -T1 -19 --no-progress "$uppercase_raw" -o "$uppercase_archive"
expect_failure "uppercase newc header fields" \
    "$tool" verify-archive --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" \
    --archive "$uppercase_archive"

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
if [ -e "$scratch/dynamic-stage/usr/bin/tinfoil-initrd" ]; then
    echo "FAIL: rejected dynamic entrypoint was copied into staging" >&2
    exit 1
fi

provenance_artifacts="$scratch/provenance-artifacts"
cp -a "$(dirname "$artifacts")" "$provenance_artifacts"
sed 's/\tsource-build\t/\tvendored\t/' "$artifacts" > "$provenance_artifacts/artifacts.tsv"
expect_failure "a forged builder source kind" \
    "$tool" stage --manifest "$manifest" --artifacts "$provenance_artifacts/artifacts.tsv" --artifact-lock "$artifact_lock" --stage "$scratch/provenance-stage"

artifact_revision_dir="$scratch/artifact-revision"
cp -a "$(dirname "$artifacts")" "$artifact_revision_dir"
sed -E 's/tinfoil-tree:[a-f0-9]{40}/tinfoil-tree:0000000000000000000000000000000000000000/' \
    "$artifacts" > "$artifact_revision_dir/artifacts.tsv"
expect_failure "a forged builder source revision" \
    "$tool" stage --manifest "$manifest" --artifacts "$artifact_revision_dir/artifacts.tsv" --artifact-lock "$artifact_lock" --stage "$scratch/artifact-revision-stage"

artifact_parameters_dir="$scratch/artifact-parameters"
cp -a "$(dirname "$artifacts")" "$artifact_parameters_dir"
sed 's/go1\.25\.7/go1.25.8/' "$artifacts" > "$artifact_parameters_dir/artifacts.tsv"
expect_failure "forged builder build parameters" \
    "$tool" stage --manifest "$manifest" --artifacts "$artifact_parameters_dir/artifacts.tsv" --artifact-lock "$artifact_lock" --stage "$scratch/artifact-parameters-stage"

source_kind_lock="$scratch/source-kind.lock.tsv"
sed 's/\tsource-build\t/\tvendored\t/' "$artifact_lock" > "$source_kind_lock"
expect_failure "a changed locked source kind" \
    "$tool" stage --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$source_kind_lock" --stage "$scratch/source-kind-stage"

source_revision_lock="$scratch/source-revision.lock.tsv"
sed -E 's/tinfoil-tree:[a-f0-9]{40}/tinfoil-tree:0000000000000000000000000000000000000000/' "$artifact_lock" > "$source_revision_lock"
expect_failure "a changed locked source revision" \
    "$tool" stage --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$source_revision_lock" --stage "$scratch/source-revision-stage"

build_parameters_lock="$scratch/build-parameters.lock.tsv"
sed 's/go1\.25\.7/go1.25.8/' "$artifact_lock" > "$build_parameters_lock"
expect_failure "changed locked build parameters" \
    "$tool" stage --manifest "$manifest" --artifacts "$artifacts" --artifact-lock "$build_parameters_lock" --stage "$scratch/build-parameters-stage"

setuid_manifest="$scratch/setuid.tsv"
sed 's#/usr/bin/tinfoil-initrd\tfile\t0755#/usr/bin/tinfoil-initrd\tfile\t4755#' "$manifest" > "$setuid_manifest"
expect_failure "a setuid manifest entry" \
    "$tool" stage --manifest "$setuid_manifest" --artifacts "$artifacts" --artifact-lock "$artifact_lock" --stage "$scratch/setuid-stage"

extra_artifact_dir="$scratch/extra-artifacts"
cp -a "$(dirname "$artifacts")" "$extra_artifact_dir"
extra_artifacts="$extra_artifact_dir/artifacts.tsv"
cp "$artifacts" "$extra_artifacts"
sed -n $'s/^tinfoil-initrd\t/unexpected\t/p' "$artifacts" >> "$extra_artifacts"
expect_failure "an undeclared builder artifact" \
    "$tool" stage --manifest "$manifest" --artifacts "$extra_artifacts" --artifact-lock "$artifact_lock" --stage "$scratch/extra-artifact-stage"

printf '%s\n' 'module-free initrd policy passed'
printf '%s\n' 'additive initrd negative tests passed'
