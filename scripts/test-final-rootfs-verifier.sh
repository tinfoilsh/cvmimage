#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="$repo_dir/scripts/verify-final-rootfs.py"
manifest_tool="$repo_dir/scripts/rootfs_manifest.py"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/final-rootfs-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

fail() { echo "test-final-rootfs-verifier: $*" >&2; exit 1; }

python3 - "$verifier" "$scratch" <<'PY'
import binascii
import importlib.util
import os
import pathlib
import stat
import struct
import sys
import types
import uuid

verifier, scratch = sys.argv[1:]
spec = importlib.util.spec_from_file_location("verify_final_rootfs", verifier)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

sectors = 8192
entry_sectors = module.GPT_ENTRY_COUNT * module.GPT_ENTRY_SIZE // module.SECTOR_SIZE


def image(path, partitions, first_usable=module.FIRST_USABLE_LBA):
    data = bytearray(sectors * module.SECTOR_SIZE)
    data[510:512] = b"\x55\xaa"
    size = sectors - 1
    data[446:462] = struct.pack("<B3sB3sII", 0, b"\0" * 3, 0xEE, b"\0" * 3, 1, size)
    entries = bytearray(module.GPT_ENTRY_COUNT * module.GPT_ENTRY_SIZE)
    for number, type_uuid, label, first, last, attributes in partitions:
        raw_label = label.encode("utf-16le").ljust(72, b"\0")
        module.ENTRY.pack_into(entries, (number - 1) * module.GPT_ENTRY_SIZE,
                               type_uuid.bytes_le, uuid.uuid4().bytes_le,
                               first, last, attributes, raw_label)
    entries_crc = binascii.crc32(entries) & 0xffffffff
    disk_uuid = uuid.uuid4().bytes_le
    last_usable = sectors - entry_sectors - 2

    def header(current, backup, entries_lba):
        block = bytearray(module.SECTOR_SIZE)
        module.HEADER.pack_into(block, 0, b"EFI PART", 0x10000, module.HEADER.size,
                                0, 0, current, backup, first_usable, last_usable,
                                disk_uuid, entries_lba, module.GPT_ENTRY_COUNT,
                                module.GPT_ENTRY_SIZE, entries_crc)
        struct.pack_into("<I", block, 16,
                         binascii.crc32(block[:module.HEADER.size]) & 0xffffffff)
        return block

    data[module.SECTOR_SIZE:2 * module.SECTOR_SIZE] = header(1, sectors - 1, 2)
    data[2 * module.SECTOR_SIZE:(2 + entry_sectors) * module.SECTOR_SIZE] = entries
    backup_lba = sectors - 1 - entry_sectors
    data[backup_lba * module.SECTOR_SIZE:(sectors - 1) * module.SECTOR_SIZE] = entries
    data[(sectors - 1) * module.SECTOR_SIZE:] = header(sectors - 1, 1, backup_lba)
    pathlib.Path(path).write_bytes(data)


def accepted(name, partitions, **geometry):
    path = pathlib.Path(scratch, name)
    image(path, partitions, **geometry)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        return module.inspect_gpt(descriptor)
    finally:
        os.close(descriptor)


root = module.ROOT_TYPE
linux = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
readonly = module.ROOT_ATTRIBUTES
partition = accepted("valid-aligned.raw", [(1, root, "root", 2048, 4095, readonly)])
assert partition.number == 1 and partition.label == "root" and partition.attributes == readonly

bad = {
    "wrong-type.raw": [(1, linux, "root", 2048, 4095, readonly)],
    "wrong-label.raw": [(1, root, "ROOT", 2048, 4095, readonly)],
    "wrong-attributes.raw": [(1, root, "root", 2048, 4095, 0)],
    "multiple.raw": [(1, root, "root", 2048, 4095, readonly),
                     (2, root, "other", 4096, 6143, readonly)],
    "ambiguous.raw": [(1, root, "root", 2048, 4095, readonly),
                      (2, linux, "root", 4096, 6143, 0)],
}
for name, partitions in bad.items():
    try:
        accepted(name, partitions)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted malformed GPT: {name}")

for name, first_usable in (("legacy-lba34.raw", 34), ("drifted-lba2049.raw", 2049)):
    try:
        accepted(name, [(1, root, "root", 2048, 4095, readonly)],
                 first_usable=first_usable)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted non-contract first usable LBA: {first_usable}")

corrupt = pathlib.Path(scratch, "corrupt-backup.raw")
image(corrupt, [(1, root, "root", 2048, 4095, readonly)])
with corrupt.open("r+b") as output:
    output.seek((sectors - 2) * module.SECTOR_SIZE)
    byte = output.read(1)
    output.seek(-1, os.SEEK_CUR)
    output.write(bytes([byte[0] ^ 1]))
descriptor = os.open(corrupt, os.O_RDONLY)
try:
    module.inspect_gpt(descriptor)
except module.VerificationError:
    pass
else:
    raise SystemExit("accepted corrupt backup GPT")
finally:
    os.close(descriptor)

expected_device = os.makedev(7, 201)
device_state = types.SimpleNamespace(
    st_mode=stat.S_IFBLK | 0o600,
    st_rdev=expected_device,
    st_dev=1,
    st_ino=2,
)
opened = []
mounted = []
original_open = module.os.open
original_fstat = module.os.fstat
original_libc = module.libc


class FakeLibc:
    @staticmethod
    def mount(source, target, filesystem, flags, options):
        mounted.append((source, target, filesystem, flags, options))
        return 0


try:
    module.os.open = lambda path, flags: opened.append((path, flags)) or 73
    module.os.fstat = lambda descriptor: device_state
    descriptor, state = module.open_partition_device(
        "/dev/loop0p1", os.major(expected_device), os.minor(expected_device)
    )
    replacement_device = os.makedev(7, 202)
    assert replacement_device != state[1]
    module.libc = FakeLibc()
    module.mount_root(descriptor, state, "/run/pinned-root")
finally:
    module.os.open = original_open
    module.os.fstat = original_fstat
    module.libc = original_libc

assert opened and opened[0][0] == "/dev/loop0p1"
assert mounted and mounted[0][0] == b"/proc/self/fd/73"
PY

mkdir "$scratch/paths"
printf x >"$scratch/paths/image.raw"
printf x >"$scratch/paths/manifest.tsv"
ln -s image.raw "$scratch/paths/image-link.raw"
ln -s manifest.tsv "$scratch/paths/manifest-link.tsv"
ln -s paths "$scratch/paths-link"
if "$verifier" --image "$scratch/paths/image-link.raw" --manifest "$scratch/paths/manifest.tsv" 2>/dev/null; then
    fail "accepted symlinked image"
fi
if "$verifier" --image "$scratch/paths/image.raw" --manifest "$scratch/paths/manifest-link.tsv" 2>/dev/null; then
    fail "accepted symlinked manifest"
fi
if "$verifier" --image "$scratch/paths-link/image.raw" --manifest "$scratch/paths/manifest.tsv" 2>/dev/null; then
    fail "accepted symlinked path ancestor"
fi
if "$verifier" --image paths/image.raw --manifest "$scratch/paths/manifest.tsv" 2>/dev/null; then
    fail "accepted relative image path"
fi
if "$verifier" --image "$scratch/paths/../paths/image.raw" --manifest "$scratch/paths/manifest.tsv" 2>/dev/null; then
    fail "accepted non-normalized image path"
fi
if "$verifier" --image "$scratch/paths//image.raw" --manifest "$scratch/paths/manifest.tsv" 2>/dev/null; then
    fail "accepted duplicate path separator"
fi

mkdir "$scratch/hostile-path"
cat >"$scratch/hostile-path/python3" <<EOF
#!/usr/bin/env bash
touch "$scratch/path-python-ran"
exit 99
EOF
chmod +x "$scratch/hostile-path/python3"
set +e
PATH="$scratch/hostile-path:$PATH" "$verifier" \
    --image "$scratch/paths/image.raw" --manifest "$scratch/paths/manifest.tsv" \
    >/dev/null 2>&1
status=$?
set -e
[[ "$status" != 99 && ! -e "$scratch/path-python-ran" ]] \
    || fail "direct invocation used a PATH-selected Python interpreter"

mkdir "$scratch/xattr-root"
printf payload >"$scratch/xattr-root/file"
if python3 - "$scratch/xattr-root/file" <<'PY'
import os, sys
try:
    os.setxattr(sys.argv[1], "user.validatefs.probe", b"bound")
except OSError:
    raise SystemExit(77)
PY
then
    "$manifest_tool" inventory --root "$scratch/xattr-root" --output "$scratch/with-xattr.tsv"
    python3 - "$scratch/xattr-root/file" <<'PY'
import os, sys
os.removexattr(sys.argv[1], "user.validatefs.probe")
PY
    "$manifest_tool" inventory --root "$scratch/xattr-root" --output "$scratch/without-xattr.tsv"
    if "$manifest_tool" compare --expected "$scratch/with-xattr.tsv" --actual "$scratch/without-xattr.tsv" >/dev/null 2>&1; then
        fail "user.validatefs xattr mismatch was filtered"
    fi
else
    echo "SKIP: filesystem does not support user xattrs" >&2
fi

if [[ "${FINAL_ROOTFS_PRIVILEGED_TEST:-0}" == 1 ]]; then
    [[ "$(id -u)" == 0 ]] || fail "privileged test requested without root"
    [[ -n "${FINAL_ROOTFS_TEST_IMAGE:-}" && -n "${FINAL_ROOTFS_TEST_MANIFEST:-}" ]] \
        || fail "set FINAL_ROOTFS_TEST_IMAGE and FINAL_ROOTFS_TEST_MANIFEST"
    env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LC_ALL=C LANG=C /usr/bin/python3 -I "$verifier" \
        --image "$FINAL_ROOTFS_TEST_IMAGE" --manifest "$FINAL_ROOTFS_TEST_MANIFEST"
else
    echo "SKIP: set FINAL_ROOTFS_PRIVILEGED_TEST=1 with produced image inputs" >&2
fi

echo "final rootfs verifier tests passed"
