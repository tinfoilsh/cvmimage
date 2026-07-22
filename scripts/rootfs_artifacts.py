#!/usr/bin/env python3

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

FIELDS = 13
NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PRODUCERS = {"go", "nvattest", "nvidia-modules"}
EXPECTED = {
    "tinfoil-init": ("go", "file", "artifacts/tinfoil-init", "0755", "-", "/usr/bin/tinfoil-init", "source-build"),
    "tinfoil-boot": ("go", "file", "artifacts/tinfoil-boot", "0755", "-", "/usr/bin/tinfoil-boot", "source-build"),
    "tinfoil-container-status": ("go", "file", "artifacts/tinfoil-container-status", "0755", "-", "/usr/bin/tinfoil-container-status", "source-build"),
    "tinfoil-egress": ("go", "file", "artifacts/tinfoil-egress", "0755", "-", "/usr/bin/tinfoil-egress", "source-build"),
    "tinfoil-shim": ("go", "file", "artifacts/tinfoil-shim", "0755", "-", "/usr/bin/tinfoil-shim", "source-build"),
    "nvattest": ("nvattest", "file", "usr/bin/nvattest", "0755", "-", "/usr/bin/nvattest", "source-build"),
    "libnvat.so.1.2.2": ("nvattest", "file", "usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2", "0644", "-", "/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2", "source-build"),
    "libnvat.so.1": ("nvattest", "symlink", "-", "0777", "libnvat.so.1.2.2", "/usr/lib/x86_64-linux-gnu/libnvat.so.1", "assembly-declaration"),
    "libnvat.so": ("nvattest", "symlink", "-", "0777", "libnvat.so.1", "/usr/lib/x86_64-linux-gnu/libnvat.so", "assembly-declaration"),
    "nvidia.ko": ("nvidia-modules", "file", "artifacts/nvidia.ko", "0644", "-", "/usr/lib/tinfoil/kernel-modules/nvidia.ko", "source-build"),
    "nvidia-uvm.ko": ("nvidia-modules", "file", "artifacts/nvidia-uvm.ko", "0644", "-", "/usr/lib/tinfoil/kernel-modules/nvidia-uvm.ko", "source-build"),
    "nvidia-modeset.ko": ("nvidia-modules", "file", "artifacts/nvidia-modeset.ko", "0644", "-", "/usr/lib/tinfoil/kernel-modules/nvidia-modeset.ko", "source-build"),
}
SUPPORT_PATHS = {
    "go": {"artifacts.tsv", "artifacts/tinfoil-initrd"},
    "nvattest": {".stamp"},
    "nvidia-modules": {".tinfoil-owned"},
}


@dataclass(frozen=True)
class Entry:
    producer: str
    name: str
    kind: str
    source_path: str
    mode: str
    uid: str
    gid: str
    sha256: str
    link_target: str
    destination: str
    source_kind: str
    source_revision: str
    build_parameters: str


def fail(message: str) -> None:
    raise ValueError(message)


def lines(content: str):
    for number, raw in enumerate(content.splitlines(), 1):
        if raw and not raw.startswith("#"):
            yield number, raw


def metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def verify_node_metadata(descriptor: int, metadata: os.stat_result, label: str, regular: bool = False) -> None:
    opened = os.fstat(descriptor)
    if metadata_identity(metadata) != metadata_identity(opened):
        fail(f"{label}: source changed while opening")
    attributes = os.listxattr(descriptor)
    if attributes:
        fail(f"{label}: source xattrs are forbidden: {sorted(attributes)}")
    if regular and opened.st_nlink != 1:
        fail(f"{label}: external hardlinks are forbidden")


def open_contract(path: Path) -> tuple[int, int]:
    components = path.parts[1:] if path.is_absolute() else path.parts
    if not components or any(component in {"", ".", ".."} for component in components):
        fail(f"{path}: contract path must be canonical")
    descriptor = os.open(
        "/" if path.is_absolute() else ".",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        for component in components[:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        contract = os.open(
            components[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        return descriptor, contract
    except OSError as error:
        os.close(descriptor)
        fail(f"{path}: contract must be a regular non-symlink file: {error}")


def read_contract(path: Path, descriptor: int) -> tuple[str, os.stat_result]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{path}: contract must be a regular non-symlink file")
    with os.fdopen(os.dup(descriptor), "rb") as source:
        content = source.read()
    stable = os.fstat(descriptor)
    if metadata_identity(metadata) != metadata_identity(stable):
        fail(f"{path}: contract changed while reading")
    try:
        return content.decode("utf-8"), stable
    except UnicodeDecodeError as error:
        fail(f"{path}: contract is not UTF-8: {error}")


def canonical_relative(value: str, label: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or pure == PurePosixPath(".") or ".." in pure.parts or str(pure) != value:
        fail(f"{label}: invalid relative path: {value}")
    return pure


def canonical_absolute(value: str, label: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if not value.startswith("/") or value.startswith("//") or value == "/" or ".." in pure.parts or str(pure) != value:
        fail(f"{label}: invalid destination: {value}")
    return pure


def parse_content(path: Path, content: str, expected_producer: str | None = None) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    destinations: set[str] = set()
    for number, raw in lines(content):
        fields = raw.split("\t")
        if len(fields) != FIELDS:
            fail(f"{path}:{number}: expected {FIELDS} tab-separated fields")
        entry = Entry(*fields)
        label = f"{path}:{number}"
        if entry.producer not in PRODUCERS or (expected_producer and entry.producer != expected_producer):
            fail(f"{label}: unexpected producer: {entry.producer}")
        if not NAME.fullmatch(entry.name) or entry.name in entries:
            fail(f"{label}: invalid or duplicate name: {entry.name}")
        expected = EXPECTED.get(entry.name)
        actual_contract = (
            entry.producer,
            entry.kind,
            entry.source_path,
            entry.mode,
            entry.link_target,
            entry.destination,
            entry.source_kind,
        )
        if expected is None or actual_contract != expected:
            fail(f"{label}: artifact differs from fixed contract: {entry.name}")
        canonical_absolute(entry.destination, label)
        if entry.destination in destinations:
            fail(f"{label}: duplicate destination: {entry.destination}")
        if entry.mode not in {"0644", "0755", "0777"} or entry.uid != "0" or entry.gid != "0":
            fail(f"{label}: invalid mode or ownership")
        if not entry.source_kind or not entry.source_revision or not entry.build_parameters:
            fail(f"{label}: missing provenance")
        if entry.kind == "file":
            canonical_relative(entry.source_path, label)
            if not SHA256.fullmatch(entry.sha256) or entry.link_target != "-" or entry.mode == "0777":
                fail(f"{label}: invalid file metadata")
        elif entry.kind == "symlink":
            if entry.source_path != "-" or entry.sha256 != "-" or entry.mode != "0777" or not entry.link_target:
                fail(f"{label}: invalid symlink metadata")
            target = PurePosixPath(entry.link_target)
            if ".." in target.parts or str(target) != entry.link_target:
                fail(f"{label}: invalid symlink target")
        else:
            fail(f"{label}: unexpected type: {entry.kind}")
        entries[entry.name] = entry
        destinations.add(entry.destination)
    if not entries:
        fail(f"{path}: empty artifact contract")
    return entries


def parse(path: Path, expected_producer: str | None = None) -> dict[str, Entry]:
    parent_descriptor, descriptor = open_contract(path)
    try:
        content, _ = read_contract(path, descriptor)
        return parse_content(path, content, expected_producer)
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def verify_file(root_descriptor: int, entry: Entry) -> None:
    relative = canonical_relative(entry.source_path, entry.name)
    descriptor = os.dup(root_descriptor)
    try:
        parts = relative.parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            metadata = os.fstat(file_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"{entry.name}: source is not a regular file")
            if f"{stat.S_IMODE(metadata.st_mode):04o}" != entry.mode:
                fail(f"{entry.name}: source mode mismatch")
            with os.fdopen(os.dup(file_descriptor), "rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            stable = os.fstat(file_descriptor)
            if metadata_identity(metadata) != metadata_identity(stable):
                fail(f"{entry.name}: source changed while hashing")
            if digest != entry.sha256:
                fail(f"{entry.name}: source hash mismatch: {digest} != {entry.sha256}")
        finally:
            os.close(file_descriptor)
    except OSError as error:
        fail(f"{entry.name}: unsafe or missing source: {error}")
    finally:
        os.close(descriptor)


def verify_tree(
    root_descriptor: int,
    manifest_metadata: os.stat_result,
    producer: str,
    entries: dict[str, Entry],
) -> None:
    allowed = {"rootfs-artifacts.tsv"} | SUPPORT_PATHS[producer]
    allowed.update(entry.source_path for entry in entries.values() if entry.kind == "file")
    for value in tuple(allowed):
        parent = PurePosixPath(value).parent
        while parent != PurePosixPath("."):
            allowed.add(str(parent))
            parent = parent.parent
    traversal_descriptor = os.dup(root_descriptor)
    verify_node_metadata(traversal_descriptor, os.fstat(traversal_descriptor), producer)

    def walk(descriptor: int, prefix: PurePosixPath) -> None:
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as error:
            fail(f"{producer}: unable to enumerate producer output: {error}")
        for name in names:
            relative = str(prefix / name) if prefix != PurePosixPath(".") else name
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                fail(f"{producer}: unstable producer output: {relative}: {error}")
            if relative not in allowed or stat.S_ISLNK(metadata.st_mode):
                fail(f"{producer}: unexpected or symlinked producer output: {relative}")
            if relative == "rootfs-artifacts.tsv" and metadata_identity(metadata) != metadata_identity(manifest_metadata):
                fail(f"{producer}: manifest changed after reading")
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except OSError as error:
                    fail(f"{producer}: unstable producer directory: {relative}: {error}")
                try:
                    opened = os.fstat(child)
                    if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                        fail(f"{producer}: producer directory changed during traversal: {relative}")
                    verify_node_metadata(child, metadata, f"{producer}: {relative}")
                    walk(child, PurePosixPath(relative))
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                try:
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except OSError as error:
                    fail(f"{producer}: unstable producer file: {relative}: {error}")
                try:
                    verify_node_metadata(child, metadata, f"{producer}: {relative}", regular=True)
                finally:
                    os.close(child)
            else:
                fail(f"{producer}: unexpected producer output type: {relative}")

    try:
        walk(traversal_descriptor, PurePosixPath("."))
    finally:
        os.close(traversal_descriptor)


def verify(lock_path: Path, manifests: list[str]) -> None:
    locked = parse(lock_path)
    if set(locked) != set(EXPECTED):
        fail(f"lock artifact set differs from fixed contract: {sorted(set(EXPECTED) - set(locked))}")
    produced: dict[str, Entry] = {}
    for specification in manifests:
        producer, separator, value = specification.partition("=")
        if not separator or producer not in PRODUCERS:
            fail(f"invalid manifest specification: {specification}")
        manifest_path = Path(value)
        root_descriptor, manifest_descriptor = open_contract(manifest_path)
        try:
            content, manifest_metadata = read_contract(manifest_path, manifest_descriptor)
            manifest_entries = parse_content(manifest_path, content, producer)
            verify_tree(root_descriptor, manifest_metadata, producer, manifest_entries)
            for name, entry in manifest_entries.items():
                if name in produced:
                    fail(f"duplicate artifact across manifests: {name}")
                if entry.kind == "file":
                    verify_file(root_descriptor, entry)
                produced[name] = entry
        finally:
            os.close(manifest_descriptor)
            os.close(root_descriptor)
    missing = sorted(set(locked) - set(produced))
    extra = sorted(set(produced) - set(locked))
    if missing or extra:
        fail(f"artifact set mismatch: missing={missing} extra={extra}")
    for name, expected in locked.items():
        if produced[name] != expected:
            fail(f"{name}: producer manifest differs from lock")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--manifest", action="append", default=[], required=True)
    args = parser.parse_args()
    try:
        verify(args.lock, args.manifest)
    except (OSError, ValueError) as error:
        print(f"rootfs artifacts: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
