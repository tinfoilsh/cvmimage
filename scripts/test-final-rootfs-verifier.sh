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
import subprocess
import sys
import types
import uuid

verifier, scratch = sys.argv[1:]
spec = importlib.util.spec_from_file_location("verify_final_rootfs", verifier)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

assert module.ROOT_PARTITION_SIZE == 3 * 1024**3
assert module.ROOT_VERITY_PARTITION_SIZE == 256 * 1024**2
assert module.RAW_IMAGE_SIZE == 3490729984

sectors = 8192
module.RAW_IMAGE_SIZE = sectors * module.SECTOR_SIZE
for delta in (-module.SECTOR_SIZE, module.SECTOR_SIZE):
    path = pathlib.Path(scratch, f"wrong-raw-size-{delta}.raw")
    with path.open("wb") as output:
        output.truncate(module.RAW_IMAGE_SIZE + delta)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        try:
            module.inspect_gpt(descriptor)
        except module.VerificationError as error:
            if "raw image size" not in str(error):
                raise
        else:
            raise SystemExit(f"accepted raw image size delta {delta}")
    finally:
        os.close(descriptor)
entry_sectors = module.GPT_ENTRY_COUNT * module.GPT_ENTRY_SIZE // module.SECTOR_SIZE
roothash = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"
root_uuid = uuid.UUID(hex=roothash[:32])
verity_uuid = uuid.UUID(hex=roothash[32:])


def image(path, partitions, first_usable=module.FIRST_USABLE_LBA,
          disk_uuid=module.DISK_UUID):
    data = bytearray(sectors * module.SECTOR_SIZE)
    data[510:512] = b"\x55\xaa"
    size = sectors - 1
    data[446:462] = module.PROTECTIVE_MBR_PREFIX + struct.pack("<II", 1, size)
    entries = bytearray(module.GPT_ENTRY_COUNT * module.GPT_ENTRY_SIZE)
    for number, type_uuid, unique_uuid, label, first, last, attributes in partitions:
        raw_label = label.encode("utf-16le").ljust(72, b"\0")
        module.ENTRY.pack_into(entries, (number - 1) * module.GPT_ENTRY_SIZE,
                               type_uuid.bytes_le, unique_uuid.bytes_le,
                               first, last, attributes, raw_label)
    entries_crc = binascii.crc32(entries) & 0xffffffff
    disk_uuid_bytes = disk_uuid.bytes_le
    last_usable = sectors - entry_sectors - 2

    def header(current, backup, entries_lba):
        block = bytearray(module.SECTOR_SIZE)
        module.HEADER.pack_into(block, 0, b"EFI PART", 0x10000, module.HEADER.size,
                                0, 0, current, backup, first_usable, last_usable,
                                disk_uuid_bytes, entries_lba, module.GPT_ENTRY_COUNT,
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


def accepted(name, partitions, supplied_roothash=roothash, **geometry):
    path = pathlib.Path(scratch, name)
    image(path, partitions, **geometry)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        layout = module.inspect_gpt(descriptor)
        module.require_roothash_partition_ids(layout, supplied_roothash)
        return layout
    finally:
        os.close(descriptor)


linux = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
fixed = [
    (1, module.ROOT_TYPE, root_uuid, module.ROOT_LABEL, 2048, 4095,
     module.ROOT_ATTRIBUTES),
    (2, module.ROOT_VERITY_TYPE, verity_uuid, module.ROOT_VERITY_LABEL, 4096, 8151,
     module.ROOT_VERITY_ATTRIBUTES),
]
synthetic_sizes = (
    (fixed[0][5] - fixed[0][4] + 1) * module.SECTOR_SIZE,
    (fixed[1][5] - fixed[1][4] + 1) * module.SECTOR_SIZE,
)
module.ROOT_PARTITION_SIZE, module.ROOT_VERITY_PARTITION_SIZE = synthetic_sizes
layout = accepted("valid-aligned.raw", fixed)
assert layout.root.number == 1 and layout.verity.number == 2
assert module.VERITY_BLOCK_SIZE == 4096
assert module.VERITY_HASH_OFFSET == 4096
assert module.VERITY_SALT == \
    "d8f43870af05f2fb613c2bb571f911da45cfa46a77e6efeabbdd5ed760ebabde"
assert str(module.DISK_UUID) == "bd21aac6-0338-4a33-85d9-d14ccf6c5ea1"
assert module.PROTECTIVE_MBR_PREFIX == bytes.fromhex("00 00 02 00 ee ff ff ff")

for name, value in (
    ("uppercase", roothash.upper().encode()),
    ("newline", (roothash + "\n").encode()),
    ("short", roothash[:-1].encode()),
    ("non-hex", ("g" + roothash[1:]).encode()),
):
    path = pathlib.Path(scratch, f"{name}.roothash")
    path.write_bytes(value)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        module.read_roothash(descriptor)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted malformed direct roothash: {name}")
    finally:
        os.close(descriptor)

bad = {
    "missing-verity.raw": fixed[:1],
    "extra.raw": fixed + [(3, linux, uuid.uuid4(), "extra", 6144, 7167, 0)],
    "wrong-root-type.raw": [
        (1, linux, root_uuid, module.ROOT_LABEL, 2048, 4095, module.ROOT_ATTRIBUTES),
        fixed[1],
    ],
    "wrong-root-label.raw": [
        (1, module.ROOT_TYPE, root_uuid, "ROOT", 2048, 4095,
         module.ROOT_ATTRIBUTES),
        fixed[1],
    ],
    "wrong-root-attributes.raw": [
        (1, module.ROOT_TYPE, root_uuid, module.ROOT_LABEL, 2048, 4095, 0),
        fixed[1],
    ],
    "wrong-verity-type.raw": [
        fixed[0],
        (2, linux, verity_uuid, module.ROOT_VERITY_LABEL, 4096, 6143,
         module.ROOT_VERITY_ATTRIBUTES),
    ],
    "wrong-verity-label.raw": [
        fixed[0],
        (2, module.ROOT_VERITY_TYPE, verity_uuid, "root-verity", 4096, 6143,
         module.ROOT_VERITY_ATTRIBUTES),
    ],
    "wrong-verity-attributes.raw": [
        fixed[0],
        (2, module.ROOT_VERITY_TYPE, verity_uuid, module.ROOT_VERITY_LABEL, 4096,
         6143, 0),
    ],
    "gap.raw": [
        fixed[0],
        (2, module.ROOT_VERITY_TYPE, verity_uuid, module.ROOT_VERITY_LABEL, 4104,
         6151, module.ROOT_VERITY_ATTRIBUTES),
    ],
    "misaligned-root-size.raw": [
        (1, module.ROOT_TYPE, root_uuid, module.ROOT_LABEL, 2048, 4094,
         module.ROOT_ATTRIBUTES),
        (2, module.ROOT_VERITY_TYPE, verity_uuid, module.ROOT_VERITY_LABEL, 4095,
         6142, module.ROOT_VERITY_ATTRIBUTES),
    ],
    "oversized-tail-gap.raw": [
        fixed[0],
        (2, module.ROOT_VERITY_TYPE, verity_uuid, module.ROOT_VERITY_LABEL, 4096,
         8143, module.ROOT_VERITY_ATTRIBUTES),
    ],
    "wrong-root-size.raw": [
        (1, module.ROOT_TYPE, root_uuid, module.ROOT_LABEL, 2048, 4103,
         module.ROOT_ATTRIBUTES),
        (2, module.ROOT_VERITY_TYPE, verity_uuid, module.ROOT_VERITY_LABEL, 4104,
         8151, module.ROOT_VERITY_ATTRIBUTES),
    ],
    "wrong-verity-size.raw": [
        fixed[0],
        (2, module.ROOT_VERITY_TYPE, verity_uuid, module.ROOT_VERITY_LABEL, 4096,
         8143, module.ROOT_VERITY_ATTRIBUTES),
    ],
}
for name, partitions in bad.items():
    try:
        accepted(name, partitions)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted malformed GPT: {name}")

for name, bad_hash in (
    ("wrong-root-partuuid.raw", "1" + roothash[1:]),
    ("wrong-verity-partuuid.raw", roothash[:-1] + "1"),
):
    try:
        accepted(name, fixed, bad_hash)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted roothash/PARTUUID mismatch: {name}")

for name, first_usable in (("legacy-lba34.raw", 34), ("drifted-lba2049.raw", 2049)):
    try:
        accepted(name, fixed, first_usable=first_usable)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted non-contract first usable LBA: {first_usable}")

try:
    accepted("wrong-disk-uuid.raw", fixed, disk_uuid=uuid.uuid4())
except module.VerificationError:
    pass
else:
    raise SystemExit("accepted non-contract GPT disk UUID")

corrupt = pathlib.Path(scratch, "corrupt-backup.raw")
image(corrupt, fixed)
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

for name, offset in (
    ("mbr-payload.raw", 0),
    ("primary-gap-payload.raw", 34 * module.SECTOR_SIZE),
    ("verity-prefix-payload.raw", fixed[1][4] * module.SECTOR_SIZE),
    ("verity-tail-payload.raw", fixed[1][4] * module.SECTOR_SIZE
     + module.verity_tree_end(synthetic_sizes[0] // module.VERITY_BLOCK_SIZE)),
    ("tail-payload.raw", 8152 * module.SECTOR_SIZE),
):
    path = pathlib.Path(scratch, name)
    image(path, fixed)
    with path.open("r+b") as output:
        output.seek(offset)
        output.write(b"x")
    descriptor = os.open(path, os.O_RDONLY)
    try:
        module.inspect_gpt(descriptor)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted hidden payload in unused bytes: {name}")
    finally:
        os.close(descriptor)

for name, offset, value in (
    ("mbr-boot-flag.raw", 446, b"\x80"),
    ("mbr-start-chs.raw", 447, b"\x01"),
    ("mbr-end-chs.raw", 451, b"\xfe"),
):
    path = pathlib.Path(scratch, name)
    image(path, fixed)
    with path.open("r+b") as output:
        output.seek(offset)
        output.write(value)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        module.inspect_gpt(descriptor)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted non-canonical protective MBR prefix: {name}")
    finally:
        os.close(descriptor)

root_device = os.makedev(7, 201)
verity_device = os.makedev(7, 202)
device_states = {
    73: types.SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_rdev=root_device,
        st_dev=1,
        st_ino=2,
    ),
    74: types.SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_rdev=verity_device,
        st_dev=1,
        st_ino=3,
    ),
}
opened = []
commands = []
mounted = []
original_open = module.os.open
original_fstat = module.os.fstat
original_run = module.subprocess.run
original_libc = module.libc


class FakeLibc:
    @staticmethod
    def mount(source, target, filesystem, flags, options):
        mounted.append((source, target, filesystem, flags, options))
        return 0


try:
    descriptors = iter((73, 74))
    module.os.open = lambda path, flags: opened.append((path, flags)) or next(descriptors)
    module.os.fstat = lambda descriptor: device_states[descriptor]
    root_descriptor, root_state = module.open_partition_device(
        "/dev/loop0p1", os.major(root_device), os.minor(root_device)
    )
    verity_descriptor, verity_state = module.open_partition_device(
        "/dev/loop0p2", os.major(verity_device), os.minor(verity_device)
    )
    module.subprocess.run = lambda *args, **kwargs: commands.append((args, kwargs))
    partition = module.Partition(1, module.ROOT_TYPE, uuid.uuid4(), 0, 63, 0, "root")
    module.verify_verity(
        root_descriptor,
        root_state,
        verity_descriptor,
        verity_state,
        partition,
        "0" * 64,
    )
    module.libc = FakeLibc()
    module.mount_root(root_descriptor, root_state, "/run/pinned-root")
finally:
    module.os.open = original_open
    module.os.fstat = original_fstat
    module.subprocess.run = original_run
    module.libc = original_libc

assert [item[0] for item in opened] == ["/dev/loop0p1", "/dev/loop0p2"]
command, options = commands[0]
assert command[0][-3:-1] == ["/proc/self/fd/73", "/proc/self/fd/74"]
assert options["pass_fds"] == (73, 74)
assert mounted[0][0] == b"/proc/self/fd/73"


def reject_partition_state_swap(swapped_descriptor, label):
    calls = {73: 0, 74: 0}

    def changing_fstat(descriptor):
        calls[descriptor] += 1
        state = device_states[descriptor]
        if descriptor == swapped_descriptor and calls[descriptor] > 1:
            return types.SimpleNamespace(
                st_mode=state.st_mode,
                st_rdev=os.makedev(7, 250),
                st_dev=state.st_dev,
                st_ino=state.st_ino + 100,
            )
        return state

    module.os.fstat = changing_fstat
    module.subprocess.run = lambda *args, **kwargs: None
    try:
        module.verify_verity(73, root_state, 74, verity_state, partition, "0" * 64)
    except module.VerificationError as error:
        if label not in str(error):
            raise
    else:
        raise SystemExit(f"accepted swapped {label} descriptor state")
    finally:
        module.os.fstat = original_fstat
        module.subprocess.run = original_run


reject_partition_state_swap(73, "root partition")
reject_partition_state_swap(74, "verity partition")

crypto = pathlib.Path(scratch, "crypto")
crypto.mkdir()
data = crypto / "data"
hash_tree = crypto / "hash"
root_hash_file = crypto / "roothash"
data.write_bytes(bytes(range(256)) * 128)
with hash_tree.open("wb") as output:
    output.truncate(16 * module.VERITY_BLOCK_SIZE)
subprocess.run(
    [
        module.VERITYSETUP,
        "--no-superblock",
        "--format=1",
        f"--data-block-size={module.VERITY_BLOCK_SIZE}",
        f"--hash-block-size={module.VERITY_BLOCK_SIZE}",
        "--data-blocks=8",
        f"--hash-offset={module.VERITY_HASH_OFFSET}",
        "--hash=sha256",
        f"--salt={module.VERITY_SALT}",
        f"--root-hash-file={root_hash_file}",
        "format",
        data,
        hash_tree,
    ],
    check=True,
    stdout=subprocess.DEVNULL,
)
crypto_roothash = root_hash_file.read_text()
partition = module.Partition(1, module.ROOT_TYPE, uuid.uuid4(), 0, 63, 0, "root")


def verify_crypto(data_path, hash_path, supplied):
    data_descriptor = os.open(data_path, os.O_RDONLY)
    hash_descriptor = os.open(hash_path, os.O_RDONLY)
    try:
        module.verify_verity(
            data_descriptor,
            module.block_device_state(data_descriptor),
            hash_descriptor,
            module.block_device_state(hash_descriptor),
            partition,
            supplied,
        )
    finally:
        os.close(hash_descriptor)
        os.close(data_descriptor)


verify_crypto(data, hash_tree, crypto_roothash)
assert module.verity_tree_end(8) == 2 * module.VERITY_BLOCK_SIZE
assert module.verity_tree_end(128) == 2 * module.VERITY_BLOCK_SIZE
assert module.verity_tree_end(129) == 4 * module.VERITY_BLOCK_SIZE


def verify_unused(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        module.require_verity_unused_zero(
            descriptor, 0, path.stat().st_size, 8,
        )
    finally:
        os.close(descriptor)


verify_unused(hash_tree)


def flip(path, offset):
    with path.open("r+b") as output:
        output.seek(offset)
        byte = output.read(1)
        output.seek(-1, os.SEEK_CUR)
        output.write(bytes([byte[0] ^ 1]))


def rejected_crypto(name, mutate, supplied=crypto_roothash):
    data_copy = crypto / f"{name}.data"
    hash_copy = crypto / f"{name}.hash"
    data_copy.write_bytes(data.read_bytes())
    hash_copy.write_bytes(hash_tree.read_bytes())
    mutate(data_copy, hash_copy)
    try:
        verify_crypto(data_copy, hash_copy, supplied)
    except subprocess.CalledProcessError:
        return
    raise SystemExit(f"accepted cryptographically unbound input: {name}")


rejected_crypto("data-mutation", lambda data_path, _hash_path: flip(data_path, 0))
rejected_crypto(
    "hash-mutation",
    lambda _data_path, hash_path: flip(hash_path, module.VERITY_HASH_OFFSET),
)
rejected_crypto("roothash-mutation", lambda _data_path, _hash_path: None,
                "1" + crypto_roothash[1:])

for name, offset in (
    ("nonzero-prefix", 0),
    ("nonzero-trailing-byte", module.verity_tree_end(8)),
    ("nonzero-final-byte", hash_tree.stat().st_size - 1),
):
    hash_copy = crypto / f"{name}.hash"
    hash_copy.write_bytes(hash_tree.read_bytes())
    flip(hash_copy, offset)
    try:
        verify_unused(hash_copy)
    except module.VerificationError:
        pass
    else:
        raise SystemExit(f"accepted nonzero unused verity bytes: {name}")
PY

mkdir "$scratch/paths"
printf x >"$scratch/paths/image.raw"
printf x >"$scratch/paths/manifest.tsv"
printf '%064d' 0 >"$scratch/paths/roothash"
ln -s image.raw "$scratch/paths/image-link.raw"
ln -s manifest.tsv "$scratch/paths/manifest-link.tsv"
ln -s roothash "$scratch/paths/roothash-link"
ln -s paths "$scratch/paths-link"
if "$verifier" --image "$scratch/paths/image-link.raw" --manifest "$scratch/paths/manifest.tsv" \
    --roothash "$scratch/paths/roothash" 2>/dev/null; then
    fail "accepted symlinked image"
fi
if "$verifier" --image "$scratch/paths/image.raw" --manifest "$scratch/paths/manifest-link.tsv" \
    --roothash "$scratch/paths/roothash" 2>/dev/null; then
    fail "accepted symlinked manifest"
fi
if "$verifier" --image "$scratch/paths/image.raw" --manifest "$scratch/paths/manifest.tsv" \
    --roothash "$scratch/paths/roothash-link" 2>/dev/null; then
    fail "accepted symlinked roothash"
fi
if "$verifier" --image "$scratch/paths-link/image.raw" --manifest "$scratch/paths/manifest.tsv" \
    --roothash "$scratch/paths/roothash" 2>/dev/null; then
    fail "accepted symlinked path ancestor"
fi
if "$verifier" --image paths/image.raw --manifest "$scratch/paths/manifest.tsv" \
    --roothash "$scratch/paths/roothash" 2>/dev/null; then
    fail "accepted relative image path"
fi
if "$verifier" --image "$scratch/paths/../paths/image.raw" --manifest "$scratch/paths/manifest.tsv" \
    --roothash "$scratch/paths/roothash" 2>/dev/null; then
    fail "accepted non-normalized image path"
fi
if "$verifier" --image "$scratch/paths//image.raw" --manifest "$scratch/paths/manifest.tsv" \
    --roothash "$scratch/paths/roothash" 2>/dev/null; then
    fail "accepted duplicate path separator"
fi

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
    [[ -n "${FINAL_ROOTFS_TEST_IMAGE:-}" && -n "${FINAL_ROOTFS_TEST_MANIFEST:-}" \
        && -n "${FINAL_ROOTFS_TEST_ROOTHASH:-}" ]] \
        || fail "set FINAL_ROOTFS_TEST_IMAGE, FINAL_ROOTFS_TEST_MANIFEST, and FINAL_ROOTFS_TEST_ROOTHASH"
    env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LC_ALL=C LANG=C /usr/bin/python3 -I "$verifier" \
        --image "$FINAL_ROOTFS_TEST_IMAGE" --manifest "$FINAL_ROOTFS_TEST_MANIFEST" \
        --roothash "$FINAL_ROOTFS_TEST_ROOTHASH"
else
    echo "SKIP: set FINAL_ROOTFS_PRIVILEGED_TEST=1 with produced image inputs" >&2
fi

echo "final rootfs verifier tests passed"
