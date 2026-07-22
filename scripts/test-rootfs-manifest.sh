#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tool="$repo_dir/scripts/rootfs_manifest.py"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/rootfs-manifest-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

fail() {
    echo "test-rootfs-manifest.sh: $*" >&2
    exit 1
}

expect_failure() {
    local expected_rc="$1"
    shift
    set +e
    "$@" >"$scratch/stdout" 2>"$scratch/stderr"
    local actual_rc="$?"
    set -e
    [[ "$actual_rc" -eq "$expected_rc" ]] || {
        cat "$scratch/stdout" >&2
        cat "$scratch/stderr" >&2
        fail "expected exit $expected_rc, got $actual_rc: $*"
    }
}

field() {
    local manifest="$1"
    local path="$2"
    local number="$3"
    awk -F '\t' -v path="$path" -v number="$number" '$1 == path { print $number; found = 1 } END { exit !found }' "$manifest"
}

root="$scratch/root"
outside="$scratch/outside"
mkdir -p "$root/a-dir" "$root/z-dir" "$outside"
chmod 0750 "$root/a-dir"
printf 'plain payload\n' >"$root/plain"
printf 'hardlinked payload\n' >"$root/hard-a"
ln "$root/hard-a" "$root/hard-b"
printf 'outside payload\n' >"$outside/not-in-root"
ln -s "$outside" "$root/external-link"
ln -s '../plain' "$root/a-dir/relative-link"
mkfifo "$root/named-pipe"
python3 - "$root/unix-socket" <<'PY'
import socket
import sys

server = socket.socket(socket.AF_UNIX)
server.bind(sys.argv[1])
server.close()
PY

xattr_supported=0
if python3 - "$root/plain" <<'PY'
import os
import sys

try:
    os.setxattr(sys.argv[1], "user.z-last", b"last")
    os.setxattr(sys.argv[1], "user.a-first", b"\x00first")
except OSError:
    raise SystemExit(1)
PY
then
    xattr_supported=1
fi

manifest_a="$scratch/manifest-a.tsv"
manifest_b="$scratch/manifest-b.tsv"
"$tool" inventory --root "$root" --output "$manifest_a"
"$tool" inventory --root "$root" --output "$manifest_b"
cmp "$manifest_a" "$manifest_b"
"$tool" validate "$manifest_a"
"$tool" compare --expected "$manifest_a" --actual "$manifest_b"

[[ "$(field "$manifest_a" / 2)" == "dir" ]] || fail "root directory record missing"
[[ "$(field "$manifest_a" /plain 2)" == "file" ]] || fail "regular file type missing"
[[ "$(field "$manifest_a" /external-link 2)" == "symlink" ]] || fail "symlink type missing"
[[ "$(field "$manifest_a" /named-pipe 2)" == "fifo" ]] || fail "FIFO type missing"
[[ "$(field "$manifest_a" /unix-socket 2)" == "socket" ]] || fail "socket type missing"
[[ "$(field "$manifest_a" /a-dir 3)" == "0750" ]] || fail "mode was not captured"
[[ "$(field "$manifest_a" /external-link 6)" == target64:* ]] || fail "symlink target is not encoded"
[[ "$(field "$manifest_a" /hard-a 8)" == "path64:L2hhcmQtYQ==" ]] || fail "hardlink root is wrong"
[[ "$(field "$manifest_a" /hard-b 8)" == "path64:L2hhcmQtYQ==" ]] || fail "hardlink group is wrong"
[[ "$(field "$manifest_a" /plain 6)" == sha256:* ]] || fail "file digest is missing"
if [[ "$xattr_supported" -eq 1 ]]; then
    [[ "$(field "$manifest_a" /plain 7)" == '{"user.a-first":"AGZpcnN0","user.z-last":"bGFzdA=="}' ]] \
        || fail "xattrs are missing or non-canonical"
fi
if grep -Fq '/not-in-root' "$manifest_a"; then
    fail "inventory followed a symlink outside the selected root"
fi

python3 - "$manifest_a" <<'PY'
import sys

paths = [line.split(b"\t", 1)[0] for line in open(sys.argv[1], "rb") if line and not line.startswith(b"#")]
if paths != sorted(paths):
    raise SystemExit("manifest paths are not in bytewise order")
if not open(sys.argv[1], "rb").read().endswith(b"\n"):
    raise SystemExit("manifest has no final newline")
PY

added_root="$scratch/added-root"
cp -a "$root" "$added_root"
printf 'new\n' >"$added_root/added"
added_manifest="$scratch/added.tsv"
"$tool" inventory --root "$added_root" --output "$added_manifest"
expect_failure 1 "$tool" compare --expected "$manifest_a" --actual "$added_manifest"
grep -Fq $'difference\t/added\tpath\t<absent>\t/added' "$scratch/stderr" \
    || fail "forward comparison did not report the added path"
expect_failure 1 "$tool" compare --expected "$added_manifest" --actual "$manifest_a"
grep -Fq $'difference\t/added\tpath\t/added\t<absent>' "$scratch/stderr" \
    || fail "reverse comparison did not report the missing path"

directory_root="$scratch/directory-root"
cp -a "$root" "$directory_root"
mkdir "$directory_root/added-directory"
directory_manifest="$scratch/directory.tsv"
"$tool" inventory --root "$directory_root" --output "$directory_manifest"
expect_failure 1 "$tool" compare --expected "$manifest_a" --actual "$directory_manifest"
grep -Fq $'difference\t/added-directory\tpath\t<absent>\t/added-directory' "$scratch/stderr" \
    || fail "added directory was not reported"

content_root="$scratch/content-root"
cp -a "$root" "$content_root"
printf 'changed payload\n' >"$content_root/plain"
content_manifest="$scratch/content.tsv"
"$tool" inventory --root "$content_root" --output "$content_manifest"
expect_failure 1 "$tool" compare --expected "$manifest_a" --actual "$content_manifest"
grep -Fq $'difference\t/plain\tcontent\t' "$scratch/stderr" \
    || fail "content difference was not reported"

chmod_root="$scratch/chmod-root"
cp -a "$root" "$chmod_root"
chmod 0700 "$chmod_root/a-dir"
chmod_manifest="$scratch/chmod.tsv"
"$tool" inventory --root "$chmod_root" --output "$chmod_manifest"
expect_failure 1 "$tool" compare --expected "$manifest_a" --actual "$chmod_manifest"
grep -Fq $'difference\t/a-dir\tmode\t0750\t0700' "$scratch/stderr" \
    || fail "metadata difference was not reported"

cp "$manifest_a" "$scratch/no-newline.tsv"
truncate -s -1 "$scratch/no-newline.tsv"
expect_failure 2 "$tool" validate "$scratch/no-newline.tsv"

{
    sed -n '1p' "$manifest_a"
    printf '\n'
    sed -n '2,$p' "$manifest_a"
} >"$scratch/blank-line.tsv"
expect_failure 2 "$tool" validate "$scratch/blank-line.tsv"
expect_failure 2 "$tool" compare --expected "$scratch/blank-line.tsv" --actual "$manifest_a"

{
    printf '# exact rootfs manifest\n'
    cat "$manifest_a"
} >"$scratch/comment.tsv"
"$tool" validate "$scratch/comment.tsv"
"$tool" compare --expected "$scratch/comment.tsv" --actual "$manifest_a"

python3 - "$scratch/nul-path.tsv" <<'PY'
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_bytes(
    b"/bad\0path\tfile\t0644\t0\t0\tsha256:" + b"0" * 64 + b"\t-\t-\n"
)
PY
expect_failure 2 "$tool" validate "$scratch/nul-path.tsv"

printf '/bad\tfile\t0644\t0\t0\t-\t-\n' >"$scratch/seven-fields.tsv"
expect_failure 2 "$tool" validate "$scratch/seven-fields.tsv"

{
    sed -n '2p' "$manifest_a"
    sed -n '1p' "$manifest_a"
} >"$scratch/unsorted.tsv"
expect_failure 2 "$tool" validate "$scratch/unsorted.tsv"

printf '/bad\tfile\t0644\t0\t0\tsha256:%064d\t{"user.z":"YQ==","user.a":"Yg=="}\t-\n' 0 \
    >"$scratch/noncanonical-xattrs.tsv"
expect_failure 2 "$tool" validate "$scratch/noncanonical-xattrs.tsv"

awk -F '\t' 'BEGIN { OFS = "\t" } $1 == "/hard-b" { $3 = "0600" } { print }' \
    "$manifest_a" >"$scratch/hardlink-mode.tsv"
expect_failure 2 "$tool" validate "$scratch/hardlink-mode.tsv"

symlink_ancestor="$scratch/symlink-ancestor"
mkdir "$symlink_ancestor"
ln -s "$root" "$symlink_ancestor/root-link"
expect_failure 2 "$tool" inventory --root "$symlink_ancestor/root-link" --output "$scratch/symlink-root.tsv"

output_parent="$scratch/output-parent"
mkdir "$output_parent"
ln -s "$output_parent" "$scratch/output-parent-link"
expect_failure 2 "$tool" inventory --root "$root" --output "$scratch/output-parent-link/manifest.tsv"

concurrent_output="$scratch/concurrent.tsv"
pids=()
for _ in {1..8}; do
    "$tool" inventory --root "$root" --output "$concurrent_output" &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid"
done
"$tool" validate "$concurrent_output"
if find "$scratch" -maxdepth 1 -name '.concurrent.tsv.tmp.*' -print -quit | grep -q .; then
    fail "concurrent output left a temporary file"
fi

timeout --signal=KILL 5s python3 - "$tool" "$scratch" <<'PY'
import importlib.util
import os
import pathlib
import sys

tool, scratch = sys.argv[1:]
spec = importlib.util.spec_from_file_location("rootfs_manifest_type_race", tool)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

root = pathlib.Path(scratch, "race-file-to-fifo")
root.mkdir()
(root / "candidate").write_text("payload")
original_open = os.open
mutated = False


def replace_with_fifo(path, flags, mode=0o777, *, dir_fd=None):
    global mutated
    if path == "candidate" and dir_fd is not None and not mutated:
        mutated = True
        os.unlink(path, dir_fd=dir_fd)
        os.mkfifo(path, dir_fd=dir_fd)
    return original_open(path, flags, mode, dir_fd=dir_fd)


module.os.open = replace_with_fifo
try:
    module.Inventory(root).collect()
except module.ManifestError:
    pass
else:
    raise SystemExit("regular-file-to-FIFO race was accepted")
if not mutated:
    raise SystemExit("regular-file-to-FIFO race was not exercised")
PY

python3 - "$tool" "$scratch" <<'PY'
import importlib.util
import os
import pathlib
import sys

tool, scratch = sys.argv[1:]
spec = importlib.util.spec_from_file_location("rootfs_manifest", tool)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class MutatingInventory(module.Inventory):
    def __init__(self, root, mutation):
        super().__init__(root)
        self.mutation = mutation
        self.root_reads = 0

    def _directory_names(self, directory_fd, parent_path):
        if parent_path == "/":
            self.root_reads += 1
            if self.root_reads == 2:
                self.mutation(directory_fd)
        return super()._directory_names(directory_fd, parent_path)


def expect_rejected(name, setup, mutation):
    root = pathlib.Path(scratch, name)
    root.mkdir()
    setup(root)
    try:
        MutatingInventory(root, mutation).collect()
    except module.ManifestError:
        return
    raise SystemExit(f"concurrent {name} mutation was accepted")


expect_rejected(
    "race-add",
    lambda root: None,
    lambda directory_fd: os.mkdir("added", dir_fd=directory_fd),
)
expect_rejected(
    "race-remove",
    lambda root: pathlib.Path(root, "removed").write_text("payload"),
    lambda directory_fd: os.unlink("removed", dir_fd=directory_fd),
)


class MetadataMutatingInventory(module.Inventory):
    def _walk(self, directory_fd, parent_path):
        super()._walk(directory_fd, parent_path)
        if parent_path == "/":
            os.fchmod(directory_fd, 0o700)


metadata_root = pathlib.Path(scratch, "race-metadata")
metadata_root.mkdir()
try:
    MetadataMutatingInventory(metadata_root).collect()
except module.ManifestError:
    pass
else:
    raise SystemExit("concurrent root metadata mutation was accepted")

if hasattr(os, "setxattr"):
    class XattrMutatingInventory(module.Inventory):
        def _walk(self, directory_fd, parent_path):
            super()._walk(directory_fd, parent_path)
            if parent_path == "/":
                try:
                    os.setxattr(directory_fd, "user.race-test", b"changed")
                except OSError:
                    raise module.ManifestError("xattrs unavailable")

    xattr_root = pathlib.Path(scratch, "race-xattr")
    xattr_root.mkdir()
    try:
        XattrMutatingInventory(xattr_root).collect()
    except module.ManifestError:
        pass
    else:
        raise SystemExit("concurrent root xattr mutation was accepted")
PY

bad_name_root="$scratch/bad-name-root"
mkdir "$bad_name_root"
python3 - "$bad_name_root" <<'PY'
import os
import sys

root = os.fsencode(sys.argv[1])
open(root + b"/line\nbreak", "wb").close()
PY
expect_failure 2 "$tool" inventory --root "$bad_name_root" --output "$scratch/bad-name.tsv"

bad_utf8_root="$scratch/bad-utf8-root"
mkdir "$bad_utf8_root"
python3 - "$bad_utf8_root" <<'PY'
import os
import sys

root = os.fsencode(sys.argv[1])
descriptor = os.open(root + b"/bad-\xff", os.O_CREAT | os.O_WRONLY, 0o600)
os.close(descriptor)
PY
expect_failure 2 "$tool" inventory --root "$bad_utf8_root" --output "$scratch/bad-utf8.tsv"

if [[ "$(id -u)" -eq 0 ]]; then
    privileged_root="$scratch/privileged-root"
    mkdir "$privileged_root"
    printf '#!/bin/sh\nexit 0\n' >"$privileged_root/setuid-file"
    chown 123:456 "$privileged_root/setuid-file"
    chmod 4755 "$privileged_root/setuid-file"
    printf '#!/bin/sh\nexit 0\n' >"$privileged_root/cap-file"
    chmod 0755 "$privileged_root/cap-file"
    mknod "$privileged_root/char-device" c 1 3
    mknod "$privileged_root/block-device" b 7 0
    capability_expected=0
    if command -v setcap >/dev/null && setcap cap_net_bind_service=ep "$privileged_root/cap-file"; then
        capability_expected=1
    fi
    privileged_manifest="$scratch/privileged.tsv"
    "$tool" inventory --root "$privileged_root" --output "$privileged_manifest"
    [[ "$(field "$privileged_manifest" /setuid-file 3)" == "4755" ]] || fail "setuid mode missing"
    [[ "$(field "$privileged_manifest" /setuid-file 4)" == "123" ]] || fail "uid missing"
    [[ "$(field "$privileged_manifest" /setuid-file 5)" == "456" ]] || fail "gid missing"
    [[ "$(field "$privileged_manifest" /char-device 2)" == "char" ]] || fail "char device missing"
    [[ "$(field "$privileged_manifest" /char-device 6)" == "dev:1:3" ]] || fail "char numbers missing"
    [[ "$(field "$privileged_manifest" /block-device 2)" == "block" ]] || fail "block device missing"
    [[ "$(field "$privileged_manifest" /block-device 6)" == "dev:7:0" ]] || fail "block numbers missing"
    if [[ "$capability_expected" -eq 1 ]]; then
        [[ "$(field "$privileged_manifest" /cap-file 7)" == *'security.capability'* ]] \
            || fail "file capability xattr missing"
    fi

    python3 - "$tool" "$privileged_root" <<'PY'
import importlib.util
import os
import pathlib
import stat
import sys

tool, root = sys.argv[1:]
spec = importlib.util.spec_from_file_location("rootfs_manifest_privileged", tool)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

device_candidate = pathlib.Path(root, "device-candidate")
device_candidate.write_text("payload")
original_open = os.open
device_mutated = False


def replace_regular_with_device(path, flags, mode=0o777, *, dir_fd=None):
    global device_mutated
    if path == "device-candidate" and dir_fd is not None and not device_mutated:
        device_mutated = True
        os.unlink(path, dir_fd=dir_fd)
        os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(1, 3), dir_fd=dir_fd)
    return original_open(path, flags, mode, dir_fd=dir_fd)


module.os.open = replace_regular_with_device
try:
    module.Inventory(pathlib.Path(root)).collect()
except module.ManifestError:
    pass
else:
    raise SystemExit("regular-file-to-device race was accepted")
finally:
    module.os.open = original_open
if not device_mutated:
    raise SystemExit("regular-file-to-device race was not exercised")

original = module.canonical_xattrs_for_path
mutated = False


def replace_device(path, context):
    global mutated
    if context == "/char-device" and not mutated:
        mutated = True
        device = pathlib.Path(root, "char-device")
        device.unlink()
        os.mknod(device, stat.S_IFCHR | 0o600, os.makedev(1, 5))
    return original(path, context)


module.canonical_xattrs_for_path = replace_device
try:
    module.Inventory(pathlib.Path(root)).collect()
except module.ManifestError:
    pass
else:
    raise SystemExit("concurrent special-device replacement was accepted")
PY
fi

echo "rootfs manifest tests passed"
