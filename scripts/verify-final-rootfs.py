#!/usr/bin/python3 -I

import argparse
import binascii
import ctypes
import errno
import fcntl
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


SECTOR_SIZE = 512
GPT_ENTRY_COUNT = 128
GPT_ENTRY_SIZE = 128
FIRST_USABLE_LBA = 2048
ROOT_TYPE = uuid.UUID("4f68bce3-e8cd-4db1-96e7-fbcaf984b709")
ROOT_LABEL = "root"
ROOT_ATTRIBUTES = 1 << 60
PYTHON = "/usr/bin/python3"
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LOOP_CTL_GET_FREE = 0x4C82
LOOP_CONFIGURE = 0x4C0A
LO_FLAGS_READ_ONLY = 1
LO_FLAGS_AUTOCLEAR = 4
LO_FLAGS_PARTSCAN = 8
CLONE_NEWNS = 0x00020000
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REC = 16384
MS_PRIVATE = 1 << 18
MNT_DETACH = 2
HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
ENTRY = struct.Struct("<16s16sQQQ72s")
LOOP_CONFIG = struct.Struct("<IIQQQQQIIII64s64s32sQQ8Q")
libc = ctypes.CDLL(None, use_errno=True)


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Partition:
    number: int
    type_uuid: uuid.UUID
    unique_uuid: uuid.UUID
    first_lba: int
    last_lba: int
    attributes: int
    label: str


def fail(message):
    raise VerificationError(message)


def syscall(result, operation):
    if result != 0:
        error = ctypes.get_errno()
        fail(f"{operation}: {os.strerror(error)}")


def secure_open(path_text):
    if path_text != os.path.normpath(path_text) or path_text.startswith("//"):
        fail(f"path is not normalized: {path_text}")
    path = Path(path_text)
    if not path.is_absolute() or path == Path("/"):
        fail(f"path must be an absolute file path: {path_text}")
    parts = path.parts[1:]
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            if part in ("", ".", ".."):
                fail(f"ambiguous path component in {path_text}")
            next_directory = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory
        )
    except OSError as error:
        fail(f"cannot securely open {path_text}: {error}")
    finally:
        os.close(directory)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        fail(f"input is not a regular file: {path_text}")
    return descriptor


def file_state(descriptor):
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def require_stable(descriptor, original, context):
    if file_state(descriptor) != original:
        fail(f"{context} changed during verification")


def pread_exact(descriptor, size, offset, context):
    data = os.pread(descriptor, size, offset)
    if len(data) != size:
        fail(f"{context}: truncated input")
    return data


def crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


def protective_mbr(descriptor, sectors):
    mbr = pread_exact(descriptor, SECTOR_SIZE, 0, "protective MBR")
    if mbr[510:512] != b"\x55\xaa":
        fail("protective MBR: missing signature")
    records = [mbr[446 + index * 16:462 + index * 16] for index in range(4)]
    used = [record for record in records if record[4] != 0]
    expected_size = min(sectors - 1, 0xFFFFFFFF)
    if len(used) != 1 or used[0][4] != 0xEE:
        fail("protective MBR: hybrid or missing GPT partition")
    if struct.unpack_from("<I", used[0], 8)[0] != 1:
        fail("protective MBR: GPT partition does not start at LBA 1")
    if struct.unpack_from("<I", used[0], 12)[0] != expected_size:
        fail("protective MBR: GPT partition has wrong size")
    if any(record[4] == 0 and record != b"\0" * 16 for record in records):
        fail("protective MBR: malformed unused partition entry")


def read_header(descriptor, lba, sectors, context):
    block = pread_exact(descriptor, SECTOR_SIZE, lba * SECTOR_SIZE, context)
    values = HEADER.unpack_from(block)
    signature, revision, header_size, stored_crc, reserved = values[:5]
    if signature != b"EFI PART" or revision != 0x00010000:
        fail(f"{context}: invalid GPT signature or revision")
    if header_size != HEADER.size or reserved != 0:
        fail(f"{context}: non-canonical GPT header")
    if block[header_size:] != b"\0" * (SECTOR_SIZE - header_size):
        fail(f"{context}: nonzero reserved header bytes")
    checked = bytearray(block[:header_size])
    checked[16:20] = b"\0" * 4
    if crc32(checked) != stored_crc:
        fail(f"{context}: header CRC mismatch")
    current, backup, first, last = values[5:9]
    entries_lba, count, entry_size, entries_crc = values[10:14]
    if current != lba or backup >= sectors or first > last:
        fail(f"{context}: invalid GPT bounds")
    if count != GPT_ENTRY_COUNT or entry_size != GPT_ENTRY_SIZE:
        fail(f"{context}: unexpected partition entry geometry")
    entries_size = count * entry_size
    entries = pread_exact(
        descriptor, entries_size, entries_lba * SECTOR_SIZE, f"{context} entries"
    )
    if crc32(entries) != entries_crc:
        fail(f"{context}: partition entry CRC mismatch")
    return values, entries


def decode_label(raw, context):
    try:
        text = raw.decode("utf-16le")
    except UnicodeDecodeError as error:
        fail(f"{context}: invalid UTF-16 partition label: {error}")
    label, separator, padding = text.partition("\0")
    if separator and padding.strip("\0"):
        fail(f"{context}: nonzero data after partition label")
    return label


def inspect_gpt(descriptor):
    original = file_state(descriptor)
    size = os.fstat(descriptor).st_size
    if size < 68 * SECTOR_SIZE or size % SECTOR_SIZE:
        fail("raw image has invalid 512-byte sector geometry")
    sectors = size // SECTOR_SIZE
    protective_mbr(descriptor, sectors)
    primary, entries = read_header(descriptor, 1, sectors, "primary GPT")
    backup, backup_entries = read_header(descriptor, sectors - 1, sectors, "backup GPT")
    entry_sectors = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE // SECTOR_SIZE
    if primary[6] != sectors - 1 or backup[6] != 1:
        fail("GPT headers do not point to each other")
    if primary[7:10] != backup[7:10] or primary[9] != backup[9]:
        fail("GPT headers disagree")
    if uuid.UUID(bytes_le=primary[9]).int == 0:
        fail("GPT disk UUID is zero")
    if primary[10] != 2 or backup[10] != sectors - 1 - entry_sectors:
        fail("GPT entry arrays are not in fixed locations")
    if primary[7] != FIRST_USABLE_LBA or primary[8] != sectors - entry_sectors - 2:
        fail("GPT usable range is not canonical")
    if entries != backup_entries:
        fail("primary and backup GPT entries disagree")
    partitions = []
    unique_ids = set()
    for index in range(GPT_ENTRY_COUNT):
        fields = ENTRY.unpack_from(entries, index * GPT_ENTRY_SIZE)
        if fields[0] == b"\0" * 16:
            if fields[1] != b"\0" * 16 or any(fields[2:5]) or fields[5] != b"\0" * 72:
                fail(f"GPT entry {index + 1}: malformed unused entry")
            continue
        type_uuid = uuid.UUID(bytes_le=fields[0])
        unique_uuid = uuid.UUID(bytes_le=fields[1])
        first, last, attributes = fields[2:5]
        if unique_uuid.int == 0 or unique_uuid in unique_ids:
            fail(f"GPT entry {index + 1}: invalid unique UUID")
        if first < primary[7] or last > primary[8] or first > last:
            fail(f"GPT entry {index + 1}: invalid partition bounds")
        unique_ids.add(unique_uuid)
        partitions.append(
            Partition(index + 1, type_uuid, unique_uuid, first, last, attributes,
                      decode_label(fields[5], f"GPT entry {index + 1}"))
        )
    ordered = sorted(partitions, key=lambda item: item.first_lba)
    if any(left.last_lba >= right.first_lba for left, right in zip(ordered, ordered[1:])):
        fail("GPT partitions overlap")
    typed = [partition for partition in partitions if partition.type_uuid == ROOT_TYPE]
    labelled = [partition for partition in partitions if partition.label == ROOT_LABEL]
    if len(typed) != 1 or len(labelled) != 1 or typed[0] != labelled[0]:
        fail("GPT must contain exactly one root partition with the fixed type and label")
    if typed[0].attributes != ROOT_ATTRIBUTES:
        fail("root partition does not have the fixed read-only GPT attribute")
    require_stable(descriptor, original, "raw image")
    return typed[0]


def private_mount_namespace():
    if os.geteuid() != 0:
        fail("verification requires root for loop and mount isolation")
    syscall(libc.unshare(CLONE_NEWNS), "unshare mount namespace")
    syscall(libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None), "make mounts private")


def configure_loop(image_descriptor):
    control = os.open("/dev/loop-control", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for _ in range(64):
            number = fcntl.ioctl(control, LOOP_CTL_GET_FREE)
            path = f"/dev/loop{number}"
            loop = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            config = LOOP_CONFIG.pack(
                image_descriptor, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN,
                b"", b"", b"", 0, 0, *([0] * 8),
            )
            try:
                fcntl.ioctl(loop, LOOP_CONFIGURE, config)
                return number, loop
            except OSError as error:
                os.close(loop)
                if error.errno != errno.EBUSY:
                    raise
        fail("no loop device could be configured")
    finally:
        os.close(control)


def block_device_state(descriptor):
    metadata = os.fstat(descriptor)
    return metadata.st_mode, metadata.st_rdev, metadata.st_dev, metadata.st_ino


def open_partition_device(path, major, minor):
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    state = block_device_state(descriptor)
    if not stat.S_ISBLK(state[0]) or os.major(state[1]) != major \
            or os.minor(state[1]) != minor:
        os.close(descriptor)
        fail("partition device node disagrees with sysfs")
    return descriptor, state


def wait_for_partition(loop_number, partition):
    name = f"loop{loop_number}p{partition.number}"
    sysfs = Path("/sys/class/block") / name
    device = Path("/dev") / name
    for _ in range(100):
        try:
            start = int((sysfs / "start").read_text().strip())
            size = int((sysfs / "size").read_text().strip())
            major, minor = (int(value) for value in (sysfs / "dev").read_text().split(":"))
            descriptor, state = open_partition_device(device, major, minor)
            if start != partition.first_lba or size != partition.last_lba - start + 1:
                os.close(descriptor)
                fail("kernel partition geometry disagrees with GPT")
            return descriptor, state
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.ENXIO, errno.ENODEV):
                raise
        time.sleep(0.02)
    fail("kernel did not expose the fixed root partition")


def copy_manifest(descriptor, destination):
    original = file_state(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as source, open(destination, "xb") as output:
        shutil.copyfileobj(source, output)
    require_stable(descriptor, original, "canonical manifest")


def mount_root(source_descriptor, source_state, target):
    if block_device_state(source_descriptor) != source_state:
        fail("partition block device changed before mount")
    flags = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC
    source = f"/proc/self/fd/{source_descriptor}"
    syscall(
        libc.mount(os.fsencode(source), os.fsencode(target), b"ext4", flags, b"noload"),
        "mount root partition read-only",
    )


def verify(image_descriptor, manifest_descriptor):
    image_state = file_state(image_descriptor)
    root_partition = inspect_gpt(image_descriptor)
    private_mount_namespace()
    scratch = Path(tempfile.mkdtemp(prefix="final-rootfs-verify.", dir="/run"))
    marker = scratch / ".owned-by-final-rootfs-verifier"
    marker.write_text(f"{os.getpid()}\n")
    mountpoint = scratch / "root"
    mountpoint.mkdir(mode=0o700)
    mounted = False
    loop_descriptor = None
    partition_descriptor = None
    try:
        expected = scratch / "expected.tsv"
        actual = scratch / "actual.tsv"
        copy_manifest(manifest_descriptor, expected)
        loop_number, loop_descriptor = configure_loop(image_descriptor)
        partition_descriptor, partition_state = wait_for_partition(
            loop_number, root_partition
        )
        mount_root(partition_descriptor, partition_state, mountpoint)
        mounted = True
        if block_device_state(partition_descriptor) != partition_state:
            fail("partition block device changed during mount")
        tool = Path(__file__).resolve().with_name("rootfs_manifest.py")
        environment = {"PATH": TRUSTED_PATH, "LC_ALL": "C", "LANG": "C"}
        subprocess.run(
            [PYTHON, "-I", tool, "inventory", "--root", mountpoint, "--output", actual],
            check=True,
            env=environment,
        )
        subprocess.run(
            [PYTHON, "-I", tool, "compare", "--expected", expected, "--actual", actual],
            check=True,
            env=environment,
        )
        require_stable(image_descriptor, image_state, "raw image")
    finally:
        if mounted:
            if libc.umount2(os.fsencode(mountpoint), 0) != 0:
                libc.umount2(os.fsencode(mountpoint), MNT_DETACH)
        if partition_descriptor is not None:
            os.close(partition_descriptor)
        if loop_descriptor is not None:
            os.close(loop_descriptor)
        if marker.is_file() and marker.read_text() == f"{os.getpid()}\n":
            shutil.rmtree(scratch)


def main():
    command = argparse.ArgumentParser(description="Verify a produced raw image rootfs")
    command.add_argument("--image", required=True)
    command.add_argument("--manifest", required=True)
    arguments = command.parse_args()
    image_descriptor = manifest_descriptor = None
    try:
        image_descriptor = secure_open(arguments.image)
        manifest_descriptor = secure_open(arguments.manifest)
        verify(image_descriptor, manifest_descriptor)
        print("final raw image rootfs matches the canonical manifest")
        return 0
    except (VerificationError, OSError, subprocess.CalledProcessError) as error:
        print(f"verify-final-rootfs: {error}", file=sys.stderr)
        return 2
    finally:
        for descriptor in (manifest_descriptor, image_descriptor):
            if descriptor is not None:
                os.close(descriptor)


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("verify-final-rootfs: interrupted", file=sys.stderr)
        sys.exit(130)
