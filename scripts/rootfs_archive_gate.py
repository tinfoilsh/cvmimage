#!/usr/bin/env python3

import argparse
import base64
import contextlib
import hashlib
import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from scripts import rootfs_assembly, rootfs_manifest


class GateError(ValueError):
    pass


def fail(message):
    raise GateError(message)


def checked_bytes(path):
    try:
        with rootfs_assembly.checked_descriptor(path) as (descriptor, _):
            with os.fdopen(os.dup(descriptor), "rb") as source:
                content = source.read()
            return content
    except rootfs_assembly.AssemblyError as error:
        fail(str(error))


@contextlib.contextmanager
def descriptor_reader(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as source:
        yield source


def descriptor_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@contextlib.contextmanager
def checked_archive_descriptor(path):
    with rootfs_assembly.checked_descriptor(path) as (descriptor, before):
        try:
            yield descriptor
        finally:
            after = os.fstat(descriptor)
            if descriptor_identity(before) != descriptor_identity(after) or os.listxattr(descriptor):
                fail(f"archive changed while being verified: {path}")


def archive_digest(descriptor):
    with descriptor_reader(descriptor) as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def require_ustar_header(descriptor, member):
    header = os.pread(descriptor, 512, member.offset)
    if len(header) != 512 or header[257:263] != b"ustar\0" or header[263:265] != b"00":
        fail(f"final archive member is not POSIX USTAR: {member.name}")


def parse_lock(path):
    content = checked_bytes(path)
    if len(content) != 65 or content[-1:] != b"\n":
        fail("archive lock must be one lowercase SHA-256 line")
    digest = content[:-1].decode("ascii", "strict")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        fail("archive lock must be one lowercase SHA-256 line")
    return digest


def member_path(member):
    if member.name == ".":
        return "/", ()
    rootfs_assembly.canonical(member.name)
    parts = PurePosixPath(member.name).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        fail(f"non-canonical archive member: {member.name!r}")
    return "/" + member.name, parts


def open_parent(root_descriptor, parts):
    current = os.dup(root_descriptor)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        for component in parts[:-1]:
            following = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def copy_payload(archive, member, descriptor):
    source = archive.extractfile(member)
    if source is None:
        fail(f"missing regular-file payload: {member.name}")
    remaining = member.size
    digest = hashlib.sha256()
    while remaining:
        block = source.read(min(1024 * 1024, remaining))
        if not block:
            fail(f"short regular-file payload: {member.name}")
        digest.update(block)
        view = memoryview(block)
        while view:
            written = os.write(descriptor, view)
            if not written:
                fail(f"short materialization write: {member.name}")
            view = view[written:]
        remaining -= len(block)
    if source.read(1):
        fail(f"oversized regular-file payload: {member.name}")
    return digest.hexdigest()


def require_canonical_metadata(member):
    if member.pax_headers or getattr(member, "sparse", None):
        fail(f"extended archive metadata is forbidden: {member.name}")
    if member.uid or member.gid or member.uname or member.gname or member.mtime:
        fail(f"non-canonical archive ownership or timestamp: {member.name}")


def validate_member(member, expected):
    require_canonical_metadata(member)
    if member.islnk():
        fail(f"hardlinks are forbidden: {member.name}")
    if expected.kind == "dir" and not member.isdir():
        fail(f"archive type differs from manifest: {member.name}")
    if expected.kind == "file" and not member.isfile():
        fail(f"archive type differs from manifest: {member.name}")
    if expected.kind == "symlink" and not member.issym():
        fail(f"archive type differs from manifest: {member.name}")
    if expected.kind not in ("dir", "file", "symlink"):
        fail(f"forbidden expected archive type: {expected.kind}")
    if f"{stat.S_IMODE(member.mode):04o}" != expected.mode:
        fail(f"archive mode differs from manifest: {member.name}")
    if expected.uid != "0" or expected.gid != "0" or expected.xattrs != "-" or expected.hardlink != "-":
        fail(f"expected manifest is not materializable by the fixed gate: {expected.path}")


def verify_archive(descriptor, expected):
    actual = []
    with descriptor_reader(descriptor) as raw, tarfile.open(fileobj=raw, mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            require_ustar_header(descriptor, member)
            require_canonical_metadata(member)
            destination, _ = member_path(member)
            if member.isdir():
                actual.append(rootfs_manifest.Entry(destination, "dir", f"{member.mode:04o}", "0", "0", "-", "-", "-"))
            elif member.issym():
                rootfs_assembly.safe_link(destination, member.linkname)
                value = "target64:" + base64.b64encode(member.linkname.encode()).decode()
                actual.append(rootfs_manifest.Entry(destination, "symlink", f"{member.mode:04o}", "0", "0", value, "-", "-"))
            elif member.isfile():
                digest = hashlib.file_digest(archive.extractfile(member), "sha256").hexdigest()
                actual.append(rootfs_manifest.Entry(destination, "file", f"{member.mode:04o}", "0", "0", "sha256:" + digest, "-", "-"))
            else:
                fail(f"forbidden final archive member type: {member.name}")
        rootfs_assembly.authenticate_archive_consumption(
            descriptor,
            os.fstat(descriptor).st_size,
            members,
            archive.offset,
        )
    if actual != expected:
        fail("final archive and manifest differ")


def materialize(archive_descriptor, root, expected):
    if os.geteuid() != 0:
        fail("faithful materialized inventory requires UID 0; no ownership fallback is permitted")
    root.mkdir(mode=0o700)
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    directories = []
    seen = set()
    complete = False
    try:
        with descriptor_reader(archive_descriptor) as raw, tarfile.open(fileobj=raw, mode="r:") as archive:
            for member in archive.getmembers():
                path, parts = member_path(member)
                if path in seen or path not in expected:
                    fail(f"unexpected or duplicate archive member: {path}")
                seen.add(path)
                entry = expected[path]
                validate_member(member, entry)
                if path == "/":
                    if not member.isdir():
                        fail("archive root must be a directory")
                    directories.append((os.dup(root_descriptor), entry.mode))
                    continue
                parent = open_parent(root_descriptor, parts)
                try:
                    name = parts[-1]
                    if entry.kind == "dir":
                        os.mkdir(name, 0o700, dir_fd=parent)
                        descriptor = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=parent,
                        )
                        os.fchown(descriptor, 0, 0)
                        directories.append((descriptor, entry.mode))
                    elif entry.kind == "file":
                        descriptor = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=parent,
                        )
                        try:
                            digest = copy_payload(archive, member, descriptor)
                            if entry.content != "sha256:" + digest:
                                fail(f"materialized content differs from manifest: {path}")
                            os.fchown(descriptor, 0, 0)
                            os.fchmod(descriptor, int(entry.mode, 8))
                            if os.listxattr(descriptor):
                                fail(f"materialized file has xattrs: {path}")
                        finally:
                            os.close(descriptor)
                    else:
                        target = base64.b64decode(entry.content.removeprefix("target64:"), validate=True).decode()
                        if member.linkname != target:
                            fail(f"archive symlink differs from manifest: {path}")
                        rootfs_assembly.safe_link(path, target)
                        os.symlink(target, name, dir_fd=parent)
                        os.chown(name, 0, 0, dir_fd=parent, follow_symlinks=False)
                finally:
                    os.close(parent)
        if seen != set(expected):
            fail("materialized archive inventory differs from expected manifest")
        for descriptor, mode in reversed(directories):
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, int(mode, 8))
            if os.listxattr(descriptor):
                fail("materialized directory has xattrs")
            os.close(descriptor)
        directories.clear()
        complete = True
    except (OSError, tarfile.TarError, rootfs_assembly.AssemblyError) as error:
        fail(f"cannot materialize fixed rootfs archive: {error}")
    finally:
        for descriptor, _ in directories:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        os.close(root_descriptor)
        if not complete:
            shutil.rmtree(root, ignore_errors=True)


def verify_locked_archive(descriptor, locked_digest, expected):
    if archive_digest(descriptor) != locked_digest:
        fail("rootfs archive bytes differ from the checked-in lock")
    verify_archive(descriptor, list(expected.values()))
    with tempfile.TemporaryDirectory(prefix="tinfoil-rootfs-archive-") as temporary:
        root = Path(temporary) / "root"
        materialize(descriptor, root, expected)
        realized = {entry.path: entry for entry in rootfs_manifest.Inventory(root).collect()}
        differences = rootfs_manifest.compare_manifests(expected, realized)
        if differences:
            fail("materialized rootfs inventory differs from the checked-in manifest")
        violations = rootfs_manifest.policy_violations(realized)
        if violations:
            fail("materialized rootfs inventory violates fixed policy")


def verify(archive, generated_manifest, expected_manifest, archive_lock):
    expected_bytes = checked_bytes(expected_manifest)
    generated_bytes = checked_bytes(generated_manifest)
    if generated_bytes != expected_bytes:
        fail("generated rootfs manifest is not byte-identical to the checked-in manifest")
    expected = rootfs_manifest.parse_content(Path(expected_manifest), expected_bytes)
    generated = rootfs_manifest.parse_content(Path(generated_manifest), generated_bytes)
    differences = rootfs_manifest.compare_manifests(expected, generated)
    if differences:
        fail("generated rootfs manifest differs from the checked-in manifest")
    violations = rootfs_manifest.policy_violations(expected)
    if violations:
        fail("checked-in rootfs manifest violates fixed policy")
    locked_digest = parse_lock(archive_lock)
    with checked_archive_descriptor(archive) as descriptor:
        verify_locked_archive(descriptor, locked_digest, expected)


def main():
    parser = argparse.ArgumentParser(description="Verify the exact final measured rootfs archive.")
    parser.add_argument("--archive", required=True)
    parser.add_argument("--generated-manifest", required=True)
    parser.add_argument("--expected-manifest", required=True)
    parser.add_argument("--archive-lock", required=True)
    arguments = parser.parse_args()
    verify(
        Path(arguments.archive),
        Path(arguments.generated_manifest),
        Path(arguments.expected_manifest),
        Path(arguments.archive_lock),
    )


if __name__ == "__main__":
    try:
        main()
    except (GateError, rootfs_manifest.ManifestError, rootfs_assembly.AssemblyError, OSError, ValueError) as error:
        raise SystemExit(f"rootfs archive gate: {error}") from error
