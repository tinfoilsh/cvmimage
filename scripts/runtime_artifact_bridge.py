#!/usr/bin/env python3

import argparse
import ctypes
import fcntl
import hashlib
import os
import secrets
import stat
from pathlib import Path, PurePosixPath

from scripts import rootfs_artifacts


REPO = Path(__file__).resolve().parent.parent
LOCK = Path("image/manifests/rootfs-artifacts.lock.tsv")
OUTPUT = Path("build/runtime-artifacts")
STATE = ".runtime-artifacts-state"
MARKER = ".tinfoil-runtime-artifacts-v1"
PREPARING = ".tinfoil-runtime-artifacts-preparing-v1"
SCHEMA = "tinfoil-runtime-artifacts-v1"
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
PRODUCER_ROOTS = {
    "go": Path("build/builder-work/output"),
    "nvattest": Path("build/rootfs-artifacts/nvattest"),
    "nvidia-modules": Path("kernel/out/rootfs-artifacts/nvidia-modules"),
}
EXPORTS = (
    MARKER,
    "producers/go/rootfs-artifacts.tsv",
    "producers/go/artifacts/tinfoil-init",
    "producers/go/artifacts/tinfoil-boot",
    "producers/go/artifacts/tinfoil-container-status",
    "producers/go/artifacts/tinfoil-egress",
    "producers/go/artifacts/tinfoil-shim",
    "producers/nvattest/rootfs-artifacts.tsv",
    "producers/nvattest/usr/bin/nvattest",
    "producers/nvattest/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2",
    "producers/nvidia-modules/rootfs-artifacts.tsv",
    "producers/nvidia-modules/artifacts/nvidia.ko",
    "producers/nvidia-modules/artifacts/nvidia-uvm.ko",
    "producers/nvidia-modules/artifacts/nvidia-modeset.ko",
)
BUILD_CONTENT = (
    "exports_files([\n"
    + "".join(f'    "{path}",\n' for path in EXPORTS)
    + '], visibility = ["//image:__pkg__"])\n'
).encode()


def fail(message: str) -> None:
    raise ValueError(message)


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return rootfs_artifacts.metadata_identity(metadata) + (
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def inode_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def read_descriptor(descriptor: int, path: Path | str, single_link: bool) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink != 1) or os.listxattr(descriptor):
        qualifier = "single-linked " if single_link else "xattr-free "
        fail(f"{path}: expected an {qualifier}regular file")
    with os.fdopen(os.dup(descriptor), "rb") as source:
        content = source.read()
    after = os.fstat(descriptor)
    if identity(before) != identity(after):
        fail(f"{path}: changed while reading")
    return content, after


def read_regular(path: Path) -> tuple[bytes, os.stat_result]:
    parent, descriptor = rootfs_artifacts.open_contract(path)
    try:
        return read_descriptor(descriptor, path, True)
    finally:
        os.close(descriptor)
        os.close(parent)


def mkdir(parent: int, name: str, mode: int = 0o755, accepted_modes: set[int] | None = None) -> int:
    created = False
    try:
        os.mkdir(name, mode, dir_fd=parent)
        created = True
    except FileExistsError:
        pass
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent,
    )
    if created:
        os.fchmod(descriptor, mode)
    metadata = os.fstat(descriptor)
    modes = accepted_modes or {mode}
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in modes or os.listxattr(descriptor):
        os.close(descriptor)
        fail(f"unsafe generated directory: {name}")
    return descriptor


def write_file(parent: int, name: str, content: bytes, mode: int) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
        dir_fd=parent,
    )
    try:
        os.fchmod(descriptor, mode)
        write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            fail("write returned no progress")
        remaining = remaining[written:]


def open_beneath(root: int, relative: str) -> tuple[int, int]:
    path = rootfs_artifacts.canonical_relative(relative, relative)
    parent = os.dup(root)
    try:
        for component in path.parts[:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
        descriptor = os.open(
            path.parts[-1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        return parent, descriptor
    except Exception:
        os.close(parent)
        raise


def destination_parent(root: int, relative: str) -> tuple[int, str]:
    path = rootfs_artifacts.canonical_relative(relative, relative)
    parent = os.dup(root)
    try:
        for component in path.parts[:-1]:
            child = mkdir(parent, component)
            os.close(parent)
            parent = child
        return parent, path.parts[-1]
    except Exception:
        os.close(parent)
        raise


def snapshot_file(source_root: int, source: str, output_root: int, output: str, entry) -> None:
    source_parent, source_fd = open_beneath(source_root, source)
    output_parent, output_name = destination_parent(output_root, output)
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"{entry.name}: source must be a single-linked regular file")
        if os.listxattr(source_fd):
            fail(f"{entry.name}: source xattrs are forbidden")
        if f"{stat.S_IMODE(before.st_mode):04o}" != entry.mode:
            fail(f"{entry.name}: source mode mismatch")
        destination = os.open(
            output_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            int(entry.mode, 8),
            dir_fd=output_parent,
        )
        digest = hashlib.sha256()
        try:
            os.fchmod(destination, int(entry.mode, 8))
            while chunk := os.read(source_fd, 1024 * 1024):
                digest.update(chunk)
                write_all(destination, chunk)
            os.fsync(destination)
        finally:
            os.close(destination)
        after = os.fstat(source_fd)
        if identity(before) != identity(after):
            fail(f"{entry.name}: source changed while copying")
        if digest.hexdigest() != entry.sha256:
            fail(f"{entry.name}: source hash mismatch")
    finally:
        os.close(output_parent)
        os.close(source_fd)
        os.close(source_parent)


def validate_contract(locked) -> None:
    files = [entry for entry in locked.values() if entry.kind == "file"]
    links = [entry for entry in locked.values() if entry.kind == "symlink"]
    if len(locked) != 12 or len(files) != 10 or len(links) != 2:
        fail("rootfs artifact lock must contain exactly 12 entries: 10 files and 2 symlinks")


def expected_files(locked, manifests: dict[str, bytes], marker_content: bytes) -> dict[str, tuple[int, str]]:
    files = {
        "BUILD.bazel": (0o644, hashlib.sha256(BUILD_CONTENT).hexdigest()),
        MARKER: (0o644, hashlib.sha256(marker_content).hexdigest()),
    }
    for producer in sorted(PRODUCER_ROOTS):
        relative = f"producers/{producer}/rootfs-artifacts.tsv"
        files[relative] = (0o644, hashlib.sha256(manifests[producer]).hexdigest())
    for entry in locked.values():
        if entry.kind == "file":
            relative = f"producers/{entry.producer}/{entry.source_path}"
            files[relative] = (int(entry.mode, 8), entry.sha256)
    return files


def expected_shape(files: dict[str, tuple[int, str]]) -> dict[str, int]:
    shape = {relative: mode for relative, (mode, _) in files.items()}
    for relative in tuple(shape):
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            shape.setdefault(str(parent), 0o755)
            parent = parent.parent
    return shape


def validate_tree(parent: int, name: str, files: dict[str, tuple[int, str]]) -> tuple[int, ...]:
    root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
    expected = expected_shape(files)
    seen = set()
    device = os.fstat(parent).st_dev

    def walk(descriptor: int, prefix: str) -> None:
        for child_name in sorted(os.listdir(descriptor)):
            relative = f"{prefix}/{child_name}" if prefix else child_name
            metadata = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if relative not in expected or metadata.st_uid != os.getuid() or metadata.st_dev != device:
                fail(f"unsafe generated package entry: {relative}")
            if stat.S_IMODE(metadata.st_mode) != expected[relative]:
                fail(f"generated package mode mismatch: {relative}")
            seen.add(relative)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(child_name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if identity(metadata) != identity(opened) or os.listxattr(child):
                        fail(f"generated package directory has xattrs: {relative}")
                    walk(child, relative)
                finally:
                    os.close(child)
            else:
                child = os.open(
                    child_name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    opened = os.fstat(child)
                    if identity(metadata) != identity(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or os.listxattr(child):
                        fail(f"unsafe generated package file: {relative}")
                    digest = hashlib.sha256()
                    while chunk := os.read(child, 1024 * 1024):
                        digest.update(chunk)
                    stable = os.fstat(child)
                    if identity(opened) != identity(stable) or digest.hexdigest() != files[relative][1]:
                        fail(f"generated package content mismatch: {relative}")
                finally:
                    os.close(child)

    try:
        metadata = os.fstat(root)
        if metadata.st_dev != device or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o755 or os.listxattr(root):
            fail("unsafe generated package root")
        walk(root, "")
        if seen != set(expected):
            fail(f"generated package shape mismatch: {sorted(set(expected) - seen)}")
        return identity(metadata)
    finally:
        os.close(root)


def read_at(root: int, relative: str) -> tuple[bytes, os.stat_result]:
    parent, descriptor = open_beneath(root, relative)
    try:
        return read_descriptor(descriptor, relative, True)
    finally:
        os.close(descriptor)
        os.close(parent)


def remove_owned(parent: int, name: str, files: dict[str, tuple[int, str]]) -> None:
    validated = validate_tree(parent, name, files)
    root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
    if identity(os.fstat(root)) != validated:
        os.close(root)
        fail("generated package changed before deletion")

    def remove_contents(descriptor: int, prefix: str) -> None:
        for child_name in sorted(os.listdir(descriptor), key=lambda value: value == MARKER):
            relative = f"{prefix}/{child_name}" if prefix else child_name
            metadata = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if metadata.st_uid != os.getuid():
                fail(f"refusing to remove unowned entry: {child_name}")
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(child_name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    if identity(metadata) != identity(os.fstat(child)) or os.listxattr(child):
                        fail(f"refusing to remove changed directory: {child_name}")
                    remove_contents(child, relative)
                finally:
                    os.close(child)
                if inode_identity(os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)) != inode_identity(metadata):
                    fail(f"refusing to remove replaced directory: {child_name}")
                os.rmdir(child_name, dir_fd=descriptor)
            else:
                child = os.open(
                    child_name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    opened = os.fstat(child)
                    if identity(metadata) != identity(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or os.listxattr(child):
                        fail(f"refusing to remove changed file: {child_name}")
                    digest = hashlib.sha256()
                    while chunk := os.read(child, 1024 * 1024):
                        digest.update(chunk)
                    if identity(opened) != identity(os.fstat(child)) or relative not in files or digest.hexdigest() != files[relative][1]:
                        fail(f"refusing to remove unauthenticated file: {relative}")
                finally:
                    os.close(child)
                if identity(os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)) != identity(metadata):
                    fail(f"refusing to remove replaced file: {child_name}")
                os.unlink(child_name, dir_fd=descriptor)

    try:
        remove_contents(root, "")
    finally:
        os.close(root)
    if inode_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != validated[:2]:
        fail("generated package root changed before deletion")
    os.rmdir(name, dir_fd=parent)


def remove_staging(parent: int, name: str, preparing_content: bytes, files: dict[str, tuple[int, str]]) -> None:
    try:
        root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
    except FileNotFoundError:
        return
    try:
        metadata = os.fstat(root)
        if metadata.st_uid != os.getuid() or metadata.st_dev != os.fstat(parent).st_dev or stat.S_IMODE(metadata.st_mode) not in {0o700, 0o755} or os.listxattr(root):
            return
        try:
            preparing, preparing_metadata = read_at(root, PREPARING)
        except (FileNotFoundError, ValueError):
            preparing = None
        if preparing is None:
            try:
                marker, marker_metadata = read_at(root, MARKER)
            except (OSError, ValueError):
                return
            expected_marker = next((digest for relative, (_, digest) in files.items() if relative == MARKER), None)
            if expected_marker is None or stat.S_IMODE(marker_metadata.st_mode) != 0o644 or hashlib.sha256(marker).hexdigest() != expected_marker:
                return
        elif preparing != preparing_content or stat.S_IMODE(preparing_metadata.st_mode) != 0o600:
            return

        def remove_partial(descriptor: int) -> None:
            for child_name in sorted(os.listdir(descriptor), key=lambda value: value in {PREPARING, MARKER}):
                child_metadata = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
                if child_metadata.st_uid != os.getuid():
                    fail(f"refusing to remove unowned staging entry: {child_name}")
                if stat.S_ISDIR(child_metadata.st_mode):
                    child = os.open(child_name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        if identity(child_metadata) != identity(os.fstat(child)) or os.listxattr(child):
                            fail(f"refusing to remove changed staging directory: {child_name}")
                        remove_partial(child)
                    finally:
                        os.close(child)
                    if inode_identity(os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)) != inode_identity(child_metadata):
                        fail(f"refusing to remove replaced staging directory: {child_name}")
                    os.rmdir(child_name, dir_fd=descriptor)
                else:
                    child = os.open(
                        child_name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    try:
                        opened = os.fstat(child)
                        if identity(child_metadata) != identity(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or os.listxattr(child):
                            fail(f"refusing to remove hostile staging entry: {child_name}")
                    finally:
                        os.close(child)
                    if identity(os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)) != identity(child_metadata):
                        fail(f"refusing to remove replaced staging file: {child_name}")
                    os.unlink(child_name, dir_fd=descriptor)

        remove_partial(root)
    except (OSError, ValueError):
        return
    finally:
        os.close(root)
    try:
        if inode_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != inode_identity(metadata):
            return
        os.rmdir(name, dir_fd=parent)
    except OSError:
        pass


def renameat2(source_parent: int, source: str, destination_parent: int, destination: str, flags: int, operation: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        fail(f"renameat2 is required for atomic {operation}")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_parent, os.fsencode(source), destination_parent, os.fsencode(destination), flags) != 0:
        error = ctypes.get_errno()
        fail(f"renameat2 {operation} failed: {os.strerror(error)}")


def publish(source_parent: int, temporary: str, destination_parent: int, destination: str) -> None:
    renameat2(
        source_parent,
        temporary,
        destination_parent,
        destination,
        RENAME_NOREPLACE,
        "no-replace publication",
    )


def exchange(source_parent: int, temporary: str, destination_parent: int, destination: str) -> None:
    renameat2(source_parent, temporary, destination_parent, destination, RENAME_EXCHANGE, "exchange")


def open_build(repository: int, repository_metadata: os.stat_result) -> int:
    build = mkdir(repository, "build", accepted_modes={0o700, 0o755, 0o775})
    metadata = os.fstat(build)
    mode = stat.S_IMODE(metadata.st_mode)
    if mode == 0o775 and not (
        stat.S_IMODE(repository_metadata.st_mode) == 0o775
        and metadata.st_gid == repository_metadata.st_gid
        and repository_metadata.st_uid == os.getuid()
    ):
        os.close(build)
        fail("group-writable build directory lacks repository group trust")
    return build


def prepare() -> None:
    lock_content, _ = read_regular(REPO / LOCK)
    locked = rootfs_artifacts.parse_content(LOCK, lock_content.decode())
    if set(locked) != set(rootfs_artifacts.EXPECTED):
        fail("rootfs artifact lock differs from fixed contract")
    validate_contract(locked)
    marker_content = f"{SCHEMA}\t{hashlib.sha256(lock_content).hexdigest()}\n".encode()
    repository = os.open(REPO, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        repository_metadata = os.fstat(repository)
        build = open_build(repository, repository_metadata)
    finally:
        os.close(repository)
    build_metadata = os.fstat(build)
    if build_metadata.st_dev != repository_metadata.st_dev:
        os.close(build)
        fail("build directory crosses the repository filesystem boundary")
    state = mkdir(build, STATE, 0o700)
    state_metadata = os.fstat(state)
    if state_metadata.st_dev != build_metadata.st_dev:
        os.close(state)
        os.close(build)
        fail("runtime artifact state crosses the build filesystem boundary")
    try:
        lock_fd = os.open(
            "lock",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=state,
        )
        os.fchmod(lock_fd, 0o600)
    except FileExistsError:
        lock_fd = os.open("lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=state)
    temporary = f".runtime-artifacts.{os.getpid()}.{secrets.token_hex(8)}"
    preparing_content = f"{SCHEMA}\t{temporary}\n".encode()
    contract_files = None
    cleanup_temporary = False
    try:
        lock_metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != os.getuid() or lock_metadata.st_nlink != 1 or stat.S_IMODE(lock_metadata.st_mode) != 0o600 or os.listxattr(lock_fd):
            fail("unsafe runtime artifact preparation lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        os.mkdir(temporary, 0o700, dir_fd=state)
        cleanup_temporary = True
        output = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=state)
        try:
            os.fchmod(output, 0o700)
            output_metadata = os.fstat(output)
            if output_metadata.st_dev != build_metadata.st_dev or output_metadata.st_uid != os.getuid() or stat.S_IMODE(output_metadata.st_mode) != 0o700:
                fail("temporary runtime artifact package crosses the build filesystem boundary")
            write_file(output, PREPARING, preparing_content, 0o600)
            produced = {}
            manifests = {}
            for producer, relative_root in PRODUCER_ROOTS.items():
                source_root, manifest_fd = rootfs_artifacts.open_contract(REPO / relative_root / "rootfs-artifacts.tsv")
                try:
                    manifest_content, manifest_metadata = rootfs_artifacts.read_contract(relative_root / "rootfs-artifacts.tsv", manifest_fd)
                    if manifest_metadata.st_nlink != 1 or stat.S_IMODE(manifest_metadata.st_mode) != 0o644 or os.listxattr(manifest_fd):
                        fail(f"{producer}: manifest must be a single-linked xattr-free 0644 file")
                    entries = rootfs_artifacts.parse_content(relative_root / "rootfs-artifacts.tsv", manifest_content, producer)
                    rootfs_artifacts.verify_tree(source_root, manifest_metadata, producer, entries)
                    manifests[producer] = manifest_content.encode()
                    producer_output, _ = destination_parent(output, f"producers/{producer}/rootfs-artifacts.tsv")
                    try:
                        write_file(producer_output, "rootfs-artifacts.tsv", manifests[producer], 0o644)
                    finally:
                        os.close(producer_output)
                    for entry in entries.values():
                        if entry.kind == "file":
                            snapshot_file(source_root, entry.source_path, output, f"producers/{producer}/{entry.source_path}", entry)
                    produced.update(entries)
                finally:
                    os.close(manifest_fd)
                    os.close(source_root)
            if produced != locked:
                fail("producer manifests differ from checked-in rootfs artifact lock")
            contract_files = expected_files(locked, manifests, marker_content)
            write_file(output, "BUILD.bazel", BUILD_CONTENT, 0o644)
            write_file(output, MARKER, marker_content, 0o644)
            os.unlink(PREPARING, dir_fd=output)
            os.fchmod(output, 0o755)
            os.fsync(output)
        finally:
            os.close(output)
        validate_tree(state, temporary, contract_files)
        os.fsync(state)
        try:
            os.stat(OUTPUT.name, dir_fd=build, follow_symlinks=False)
        except FileNotFoundError:
            publish(state, temporary, build, OUTPUT.name)
            cleanup_temporary = False
            os.fsync(build)
            os.fsync(state)
            validate_tree(build, OUTPUT.name, contract_files)
        else:
            validate_tree(build, OUTPUT.name, contract_files)
            exchange(state, temporary, build, OUTPUT.name)
            cleanup_temporary = False
            os.fsync(build)
            os.fsync(state)
            try:
                validate_tree(build, OUTPUT.name, contract_files)
            except Exception as validation_error:
                try:
                    validate_tree(state, temporary, contract_files)
                    exchange(state, temporary, build, OUTPUT.name)
                    cleanup_temporary = True
                    os.fsync(build)
                    os.fsync(state)
                    validate_tree(build, OUTPUT.name, contract_files)
                except Exception as rollback_error:
                    validation_error.add_note(f"rollback failed: {rollback_error}")
                    raise validation_error from rollback_error
                raise
            validate_tree(state, temporary, contract_files)
            remove_owned(state, temporary, contract_files)
            os.fsync(state)
        os.fsync(build)
    except Exception:
        if cleanup_temporary:
            remove_staging(state, temporary, preparing_content, contract_files or {})
        raise
    finally:
        os.close(lock_fd)
        os.close(state)
        os.close(build)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("prepare")
    parser.parse_args()
    prepare()


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"runtime artifact bridge: {error}")
