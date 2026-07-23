#!/usr/bin/env python3

import argparse
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

UINT32_MAX = (1 << 32) - 1


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    content: str


def fail(message: str) -> None:
    raise ValueError(message)


def data_lines(path: Path):
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        if raw and not raw.startswith("#"):
            yield number, raw


def parse_manifest(path: Path) -> dict[str, Entry]:
    entries = {}
    for number, raw in data_lines(path):
        fields = raw.split("\t")
        if len(fields) != 6:
            fail(f"{path}:{number}: expected 6 tab-separated fields")
        destination, kind, mode_text, uid_text, gid_text, content = fields
        pure = PurePosixPath(destination)
        if (
            not destination.startswith("/")
            or destination == "/"
            or destination.startswith("//")
            or str(pure) != destination
            or ".." in pure.parts
        ):
            fail(f"{path}:{number}: invalid path: {destination}")
        if destination in entries:
            fail(f"{path}:{number}: duplicate path: {destination}")
        if kind not in {"dir", "file", "symlink"}:
            fail(f"{path}:{number}: unsupported type: {kind}")
        try:
            mode = int(mode_text, 8)
            uid = int(uid_text)
            gid = int(gid_text)
        except ValueError as error:
            fail(f"{path}:{number}: invalid numeric metadata: {error}")
        if not 0 <= mode <= 0o777:
            fail(f"{path}:{number}: mode must contain only rwx permission bits")
        if not 0 <= uid <= UINT32_MAX or not 0 <= gid <= UINT32_MAX:
            fail(f"{path}:{number}: uid/gid must fit the newc format")
        if kind == "dir" and content != "-":
            fail(f"{path}:{number}: directory content must be '-'")
        if kind == "file" and content != "tinfoil-initrd":
            fail(f"{path}:{number}: file content must be the fixed tinfoil-initrd output")
        if kind == "symlink":
            target = PurePosixPath(content)
            if (
                not content
                or target.is_absolute()
                or target == PurePosixPath(".")
                or ".." in target.parts
                or str(target) != content
            ):
                fail(f"{path}:{number}: invalid symlink target: {content}")
            if mode != 0o777:
                fail(f"{path}:{number}: symlink mode must be 0777")
        entries[destination] = Entry(destination, kind, mode, uid, gid, content)
    if not entries:
        fail(f"{path}: manifest is empty")
    for entry in entries.values():
        parent = str(PurePosixPath(entry.path).parent)
        if parent != "/" and (parent not in entries or entries[parent].kind != "dir"):
            fail(f"{entry.path}: parent must be a declared directory: {parent}")
        if entry.kind == "symlink":
            target = str(PurePosixPath(entry.path).parent / entry.content)
            if target not in entries:
                fail(f"{entry.path}: symlink target must be declared: {target}")
    files = [entry for entry in entries.values() if entry.kind == "file"]
    if len(files) != 1 or files[0].path != "/usr/bin/tinfoil-initrd":
        fail("manifest must contain only the fixed /usr/bin/tinfoil-initrd file")
    return entries


def read_binary(path: Path) -> bytes:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"tinfoil-initrd output is not a regular file: {path}")
    return path.read_bytes()


def align4(value: int) -> int:
    return (value + 3) & ~3


def cpio_record(name: str, ino: int, mode: int, uid: int, gid: int, nlink: int, data: bytes) -> bytes:
    name_data = name.encode() + b"\0"
    fields = (ino, mode, uid, gid, nlink, 0, len(data), 0, 0, 0, 0, len(name_data), 0)
    if any(value < 0 or value > UINT32_MAX for value in fields):
        fail(f"newc field overflow for {name}")
    record = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name_data
    record += b"\0" * (align4(len(record)) - len(record))
    record += data
    record += b"\0" * (align4(len(record)) - len(record))
    return record


def archive_bytes(entries: dict[str, Entry], binary: bytes) -> bytes:
    archive = bytearray()
    ordered = sorted(entries.values(), key=lambda entry: entry.path)
    for ino, entry in enumerate(ordered, 1):
        if entry.kind == "dir":
            mode = stat.S_IFDIR | entry.mode
            data = b""
            nlink = 2
        elif entry.kind == "file":
            mode = stat.S_IFREG | entry.mode
            data = binary
            nlink = 1
        else:
            mode = stat.S_IFLNK | entry.mode
            data = entry.content.encode()
            nlink = 1
        archive.extend(cpio_record(entry.path.removeprefix("/"), ino, mode, entry.uid, entry.gid, nlink, data))
    archive.extend(cpio_record("TRAILER!!!", len(ordered) + 1, 0, 0, 0, 1, b""))
    archive.extend(b"\0" * ((512 - len(archive) % 512) % 512))
    return bytes(archive)


def write_output(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
        os.chmod(temporary, 0o644)
        os.utime(temporary, (0, 0))
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def compress_archive(source: Path, output: Path) -> None:
    result = subprocess.run(
        ["zstd", "-q", "-T1", "-19", "--no-progress", "-c", str(source)],
        capture_output=True,
        check=True,
    )
    write_output(output, result.stdout)


def parse_archive(data: bytes):
    offset = 0
    entries = {}
    order = []
    while offset + 110 <= len(data):
        header = data[offset : offset + 110]
        offset += 110
        if header[:6] != b"070701":
            fail("invalid newc header")
        values = [int(header[index : index + 8], 16) for index in range(6, 110, 8)]
        ino, mode, uid, gid, nlink, mtime, size, devmajor, devminor, rdevmajor, rdevminor, namesize, check = values
        if namesize < 1 or offset + namesize > len(data):
            fail("invalid newc name size")
        name_data = data[offset : offset + namesize]
        if name_data[-1:] != b"\0":
            fail("newc name is not terminated")
        name = name_data[:-1].decode()
        offset = align4(offset + namesize)
        if offset + size > len(data):
            fail(f"truncated newc data for {name}")
        content = data[offset : offset + size]
        offset = align4(offset + size)
        if name == "TRAILER!!!":
            if any((mode, uid, gid, mtime, size, devmajor, devminor, rdevmajor, rdevminor, check)) or nlink != 1:
                fail("non-canonical newc trailer")
            expected_size = (offset + 511) & ~511
            if len(data) != expected_size or any(data[offset:]):
                fail("non-canonical data after newc trailer")
            return entries, order
        pure = PurePosixPath(name)
        if not name or pure.is_absolute() or ".." in pure.parts or str(pure) != name:
            fail(f"invalid archive path: {name}")
        path = "/" + name
        if path in entries:
            fail(f"duplicate archive path: {path}")
        entries[path] = (ino, mode, uid, gid, nlink, mtime, devmajor, devminor, rdevmajor, rdevminor, check, content)
        order.append(path)
    fail("newc archive is missing its trailer")


def verify_archive(archive: Path, entries: dict[str, Entry], binary: bytes) -> None:
    result = subprocess.run(["zstd", "-q", "-d", "-c", str(archive)], capture_output=True, check=True)
    actual, order = parse_archive(result.stdout)
    expected_order = sorted(entries)
    if order != expected_order or set(actual) != set(entries):
        fail("archive paths or ordering do not match the manifest")
    for path, entry in entries.items():
        ino, mode, uid, gid, nlink, mtime, devmajor, devminor, rdevmajor, rdevminor, check, content = actual[path]
        expected_mode = {"dir": stat.S_IFDIR, "file": stat.S_IFREG, "symlink": stat.S_IFLNK}[entry.kind] | entry.mode
        expected_content = binary if entry.kind == "file" else entry.content.encode() if entry.kind == "symlink" else b""
        if ino != expected_order.index(path) + 1 or nlink != (2 if entry.kind == "dir" else 1):
            fail(f"{path}: archive inode/link metadata mismatch")
        if mode != expected_mode or uid != entry.uid or gid != entry.gid:
            fail(f"{path}: archive type, mode, or ownership mismatch")
        if mtime != 0 or any((devmajor, devminor, rdevmajor, rdevminor, check)):
            fail(f"{path}: archive has non-deterministic metadata")
        if content != expected_content:
            fail(f"{path}: archive content mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("archive", "compress", "verify-archive"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    if args.command == "compress":
        if args.input is None or args.output is None:
            parser.error("compress requires --input and --output")
        compress_archive(args.input, args.output)
        return 0
    if args.manifest is None or args.binary is None:
        parser.error(f"{args.command} requires --manifest and --binary")
    entries = parse_manifest(args.manifest)
    binary = read_binary(args.binary)
    if args.command == "archive":
        if args.output is None:
            parser.error("archive requires --output")
        write_output(args.output, archive_bytes(entries, binary))
    else:
        if args.archive is None:
            parser.error("verify-archive requires --archive")
        verify_archive(args.archive, entries, binary)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"initrd-manifest: {error}", file=sys.stderr)
        sys.exit(1)
