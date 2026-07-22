#!/usr/bin/env python3

import argparse
import errno
import hashlib
import os
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

UINT32_MAX = (1 << 32) - 1
REPO_DIR = Path(__file__).resolve().parent.parent
STAGE_BASE = REPO_DIR / "build"
EXPECTED_SOURCE_KIND = "source-build"


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    content: str
    provenance: str


@dataclass(frozen=True)
class Artifact:
    name: str
    path: Path
    sha256: str
    mode: int
    source_kind: str
    source_revision: str
    build_parameters: str


@dataclass(frozen=True)
class ArtifactLock:
    name: str
    source_kind: str
    source_revision: str
    build_parameters: str
    sha256: str
    destination: str


def fail(message: str) -> None:
    raise ValueError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def data_lines(path: Path):
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        yield number, raw


def absolute_manifest_path(value: str, location: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if not value.startswith("/") or value == "/" or value.startswith("//"):
        fail(f"{location}: path must have exactly one leading slash and be non-root: {value}")
    if "\0" in value or str(pure) != value or ".." in pure.parts:
        fail(f"{location}: path is not normalized: {value}")
    return pure


def parse_manifest(path: Path) -> dict[str, Entry]:
    entries = {}
    for number, raw in data_lines(path):
        fields = raw.split("\t")
        if len(fields) != 7:
            fail(f"{path}:{number}: expected 7 tab-separated fields")
        destination, kind, mode_text, uid_text, gid_text, content, provenance = fields
        absolute_manifest_path(destination, f"{path}:{number}")
        reject_residue(destination)
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
        if mode < 0 or mode > 0o777:
            fail(f"{path}:{number}: mode must contain only rwx permission bits")
        if not 0 <= uid <= UINT32_MAX or not 0 <= gid <= UINT32_MAX:
            fail(f"{path}:{number}: uid/gid must fit the newc format")
        if kind == "dir" and content != "-":
            fail(f"{path}:{number}: directory content must be '-'")
        if kind == "file" and not content.startswith("artifact:"):
            fail(f"{path}:{number}: files must resolve through an artifact hash")
        if kind == "symlink" and (not content or content == "-"):
            fail(f"{path}:{number}: symlink target is required")
        if kind == "symlink":
            target = PurePosixPath(content)
            if target.is_absolute() or target == PurePosixPath(".") or ".." in target.parts or str(target) != content:
                fail(f"{path}:{number}: symlink target must be normalized, relative, and non-traversing")
            if mode != 0o777:
                fail(f"{path}:{number}: symlink mode must be 0777")
        if not provenance:
            fail(f"{path}:{number}: provenance is required")
        entries[destination] = Entry(destination, kind, mode, uid, gid, content, provenance)
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
    return entries


def parse_artifacts(path: Path) -> dict[str, Artifact]:
    artifacts = {}
    base = path.parent
    resolved_base = base.resolve(strict=True)
    for number, raw in data_lines(path):
        fields = raw.split("\t")
        if len(fields) != 7:
            fail(f"{path}:{number}: expected 7 tab-separated fields")
        name, relative, digest, mode_text, source_kind, source_revision, build_parameters = fields
        pure = PurePosixPath(relative)
        if not all((name, source_kind, source_revision, build_parameters)):
            fail(f"{path}:{number}: artifact name and provenance fields are required")
        if "\0" in relative or pure == PurePosixPath(".") or pure.is_absolute() or ".." in pure.parts or str(pure) != relative:
            fail(f"{path}:{number}: invalid artifact path: {relative}")
        if name in artifacts:
            fail(f"{path}:{number}: duplicate artifact: {name}")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            fail(f"{path}:{number}: invalid SHA-256: {digest}")
        try:
            mode = int(mode_text, 8)
        except ValueError as error:
            fail(f"{path}:{number}: invalid mode: {error}")
        if mode < 0 or mode > 0o777:
            fail(f"{path}:{number}: artifact mode must contain only rwx permission bits")
        artifact_path = base / relative
        try:
            resolved_artifact = artifact_path.resolve(strict=True)
            resolved_artifact.relative_to(resolved_base)
        except (OSError, ValueError):
            fail(f"{path}:{number}: artifact escapes its manifest directory: {relative}")
        metadata = artifact_path.lstat()
        if artifact_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            fail(f"{path}:{number}: missing artifact: {artifact_path}")
        actual = sha256_file(artifact_path)
        if actual != digest:
            fail(f"{path}:{number}: artifact hash mismatch: {name}: {actual} != {digest}")
        actual_mode = stat.S_IMODE(metadata.st_mode)
        if actual_mode != mode:
            fail(f"{path}:{number}: artifact mode mismatch: {name}: {actual_mode:04o} != {mode:04o}")
        artifacts[name] = Artifact(
            name,
            artifact_path,
            digest,
            mode,
            source_kind,
            source_revision,
            build_parameters,
        )
    if not artifacts:
        fail(f"{path}: artifact manifest is empty")
    return artifacts


def parse_artifact_locks(path: Path) -> dict[str, ArtifactLock]:
    locks = {}
    for number, raw in data_lines(path):
        fields = raw.split("\t")
        if len(fields) != 6:
            fail(f"{path}:{number}: expected 6 tab-separated fields")
        name, source_kind, source_revision, build_parameters, digest, destination = fields
        if not all((name, source_kind, source_revision, build_parameters)):
            fail(f"{path}:{number}: artifact lock provenance fields are required")
        if name in locks:
            fail(f"{path}:{number}: duplicate artifact lock: {name}")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            fail(f"{path}:{number}: invalid locked SHA-256: {digest}")
        absolute_manifest_path(destination, f"{path}:{number}")
        locks[name] = ArtifactLock(name, source_kind, source_revision, build_parameters, digest, destination)
    if not locks:
        fail(f"{path}: artifact lock is empty")
    return locks


def artifact_for(entry: Entry, artifacts: dict[str, Artifact]) -> Artifact:
    name = entry.content.removeprefix("artifact:")
    artifact = artifacts.get(name)
    if artifact is None:
        fail(f"{entry.path}: unknown artifact: {name}")
    if artifact.mode != entry.mode:
        fail(f"{entry.path}: artifact and destination modes differ")
    return artifact


def verify_artifact_locks(entries: dict[str, Entry], artifacts: dict[str, Artifact], locks: dict[str, ArtifactLock]) -> None:
    source_status = subprocess.run(
        ["git", "-C", str(REPO_DIR), "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--", "tinfoil"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if source_status:
        fail(f"refusing uncommitted or ignored tinfoil source:\n{source_status.rstrip()}")
    source_tree = subprocess.run(
        ["git", "-C", str(REPO_DIR), "rev-parse", "HEAD:tinfoil"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    expected_source_revision = f"tinfoil-tree:{source_tree}"
    used = set()
    for entry in entries.values():
        if entry.kind != "file":
            continue
        name = entry.content.removeprefix("artifact:")
        artifact = artifact_for(entry, artifacts)
        lock = locks.get(name)
        if lock is None:
            fail(f"{entry.path}: missing source-controlled artifact lock: {name}")
        if lock.sha256 != artifact.sha256:
            fail(f"{entry.path}: builder artifact differs from source lock: {artifact.sha256} != {lock.sha256}")
        if lock.destination != entry.path:
            fail(f"{entry.path}: locked destination mismatch: {lock.destination}")
        if entry.provenance != f"builder:{name}":
            fail(f"{entry.path}: manifest provenance mismatch: {entry.provenance}")
        if lock.source_kind != EXPECTED_SOURCE_KIND or artifact.source_kind != lock.source_kind:
            fail(f"{entry.path}: locked source kind mismatch: {lock.source_kind}")
        if lock.source_revision != expected_source_revision or artifact.source_revision != lock.source_revision:
            fail(f"{entry.path}: locked source revision mismatch: {lock.source_revision} != {expected_source_revision}")
        if artifact.build_parameters != lock.build_parameters:
            fail(f"{entry.path}: builder build parameters differ from source lock")
        used.add(name)
    unused = sorted(set(locks) - used)
    if unused:
        fail(f"unused source-controlled artifact locks: {unused}")
    undeclared = sorted(set(artifacts) - used)
    if undeclared:
        fail(f"undeclared builder artifacts: {undeclared}")


def stage_path(root: Path, destination: str) -> Path:
    absolute_manifest_path(destination, "internal destination")
    return root / destination[1:]


def directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def entry_parent(entry: Entry) -> tuple[str, str]:
    relative = PurePosixPath(entry.path.removeprefix("/"))
    parent = "/" if relative.parent == PurePosixPath(".") else f"/{relative.parent}"
    return parent, relative.name


def set_descriptor_metadata(descriptor: int, entry: Entry) -> None:
    os.fchmod(descriptor, entry.mode)
    os.fchown(descriptor, entry.uid, entry.gid)
    os.utime(descriptor, (0, 0))


def set_symlink_metadata(parent_descriptor: int, name: str, entry: Entry) -> None:
    os.chown(name, entry.uid, entry.gid, dir_fd=parent_descriptor, follow_symlinks=False)
    os.utime(name, (0, 0), dir_fd=parent_descriptor, follow_symlinks=False)


def normalized_stage_root(root: Path) -> tuple[Path, Path]:
    normalized = Path(os.path.abspath(root))
    stage_base = Path(os.path.abspath(STAGE_BASE))
    try:
        normalized.relative_to(stage_base)
    except ValueError:
        fail(f"staging directory must be confined beneath {stage_base}: {normalized}")
    if normalized == stage_base:
        fail(f"refusing to use the stage base itself: {stage_base}")
    current = Path("/")
    for component in normalized.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"refusing symlinked staging path component: {current}")
        if current != normalized and not stat.S_ISDIR(metadata.st_mode):
            fail(f"staging path parent is not a directory: {current}")
    marker = normalized.parent / f".{normalized.name}.tinfoil-initrd-owned"
    return normalized, marker


def claim_stage(parent_descriptor: int, marker_name: str, root: Path) -> None:
    ownership = f"tinfoil-additive-initrd-stage-v1\n{root}\n"
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(marker_name, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            create_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        descriptor = os.open(marker_name, create_flags, 0o600, dir_fd=parent_descriptor)
        with os.fdopen(descriptor, "w") as destination:
            destination.write(ownership)
        return
    with os.fdopen(descriptor) as source:
        metadata = os.fstat(source.fileno())
        contents = source.read()
    if not stat.S_ISREG(metadata.st_mode) or contents != ownership:
        fail(f"staging ownership marker is invalid: {marker_name}")


_CREATE_STAGE_ROOT_OPENED_HOOK = None


def create_stage(root: Path, entries: dict[str, Entry], artifacts: dict[str, Artifact]) -> None:
    root, marker = normalized_stage_root(root)
    verify_static(artifact_for(entries["/usr/bin/tinfoil-initrd"], artifacts).path)
    parent_descriptor, root_name = open_output_parent(root)
    marker_name = marker.name
    descriptors = {}
    try:
        try:
            root_metadata = os.stat(root_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            root_metadata = None
        if root_metadata is not None:
            if not stat.S_ISDIR(root_metadata.st_mode):
                fail(f"staging path is not a real directory: {root}")
            try:
                os.stat(marker_name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                fail(f"refusing to replace unowned staging directory: {root}")
        claim_stage(parent_descriptor, marker_name, root)
        if root_metadata is not None:
            shutil.rmtree(root_name, dir_fd=parent_descriptor)
        os.mkdir(root_name, 0o755, dir_fd=parent_descriptor)
        descriptors["/"] = os.open(root_name, directory_flags(), dir_fd=parent_descriptor)
        if _CREATE_STAGE_ROOT_OPENED_HOOK is not None:
            _CREATE_STAGE_ROOT_OPENED_HOOK(root)
        for entry in sorted(entries.values(), key=lambda item: (len(PurePosixPath(item.path).parts), item.path)):
            parent, name = entry_parent(entry)
            parent_entry_descriptor = descriptors[parent]
            if entry.kind == "dir":
                os.mkdir(name, entry.mode, dir_fd=parent_entry_descriptor)
                descriptors[entry.path] = os.open(name, directory_flags(), dir_fd=parent_entry_descriptor)
            elif entry.kind == "file":
                artifact = artifact_for(entry, artifacts)
                source_flags = os.O_RDONLY
                destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_CLOEXEC"):
                    source_flags |= os.O_CLOEXEC
                    destination_flags |= os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    source_flags |= os.O_NOFOLLOW
                    destination_flags |= os.O_NOFOLLOW
                source_descriptor = os.open(artifact.path, source_flags)
                try:
                    destination_descriptor = os.open(
                        name,
                        destination_flags,
                        entry.mode,
                        dir_fd=parent_entry_descriptor,
                    )
                    try:
                        with os.fdopen(source_descriptor, "rb", closefd=False) as source:
                            with os.fdopen(destination_descriptor, "wb", closefd=False) as destination:
                                shutil.copyfileobj(source, destination)
                    except Exception:
                        os.close(destination_descriptor)
                        raise
                    descriptors[entry.path] = destination_descriptor
                finally:
                    os.close(source_descriptor)
            else:
                os.symlink(entry.content, name, dir_fd=parent_entry_descriptor)
        for entry in sorted(
            entries.values(),
            key=lambda item: (len(PurePosixPath(item.path).parts), item.path),
            reverse=True,
        ):
            if entry.kind == "symlink":
                parent, name = entry_parent(entry)
                set_symlink_metadata(descriptors[parent], name, entry)
            else:
                set_descriptor_metadata(descriptors[entry.path], entry)
        os.fchown(descriptors["/"], 0, 0)
        os.fchmod(descriptors["/"], 0o755)
        os.utime(descriptors["/"], (0, 0))
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)
        os.close(parent_descriptor)


def tree_entries(root: Path) -> dict[str, os.stat_result]:
    actual = {}
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            relative = "/" + path.relative_to(root).as_posix()
            actual[relative] = path.lstat()
    return actual


def expected_file_hash(entry: Entry, artifacts: dict[str, Artifact]) -> str:
    return artifact_for(entry, artifacts).sha256


def reject_residue(path: str) -> None:
    forbidden = {
        "apt", "dpkg", "debconf", "systemd", "perl", "perl5", "gconv",
        "locale", "terminfo", "pam", "modules", "var", "etc", "opt", "home", "root",
    }
    components = {component.lower() for component in PurePosixPath(path).parts}
    match = sorted(components & forbidden)
    if match:
        fail(f"forbidden distro residue path {path}: {', '.join(match)}")
    lower = path.lower()
    if lower.endswith((".ko", ".ko.gz", ".ko.xz", ".ko.zst")):
        fail(f"forbidden kernel module payload: {path}")


def verify_static(path: Path) -> None:
    if path.read_bytes()[:4] != b"\x7fELF":
        fail(f"entrypoint is not ELF: {path}")
    dynamic = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True, check=False)
    if dynamic.returncode != 0:
        fail(f"readelf -d failed for {path}: {dynamic.stderr.strip()}")
    if "(NEEDED)" in dynamic.stdout:
        fail(f"entrypoint has dynamic dependencies: {path}")
    program = subprocess.run(["readelf", "-l", str(path)], capture_output=True, text=True, check=False)
    if program.returncode != 0:
        fail(f"readelf -l failed for {path}: {program.stderr.strip()}")
    if "Requesting program interpreter" in program.stdout:
        fail(f"entrypoint has a dynamic interpreter: {path}")


def verify_stage(root: Path, entries: dict[str, Entry], artifacts: dict[str, Artifact]) -> None:
    actual = tree_entries(root)
    if set(actual) != set(entries):
        missing = sorted(set(entries) - set(actual))
        unexpected = sorted(set(actual) - set(entries))
        fail(f"stage path mismatch; missing={missing}; unexpected={unexpected}")
    for path, entry in entries.items():
        reject_residue(path)
        destination = stage_path(root, path)
        metadata = actual[path]
        kind = "dir" if stat.S_ISDIR(metadata.st_mode) else "file" if stat.S_ISREG(metadata.st_mode) else "symlink" if stat.S_ISLNK(metadata.st_mode) else "special"
        if kind != entry.kind:
            fail(f"{path}: type mismatch: {kind} != {entry.kind}")
        mode = stat.S_IMODE(metadata.st_mode)
        if mode != entry.mode:
            fail(f"{path}: mode mismatch: {mode:04o} != {entry.mode:04o}")
        if metadata.st_uid != entry.uid or metadata.st_gid != entry.gid:
            fail(f"{path}: ownership mismatch: {metadata.st_uid}:{metadata.st_gid} != {entry.uid}:{entry.gid}")
        if metadata.st_mtime_ns != 0:
            fail(f"{path}: mtime is not SOURCE_DATE_EPOCH=0")
        xattrs = os.listxattr(destination, follow_symlinks=False)
        if xattrs:
            fail(f"{path}: undeclared xattrs/capabilities: {xattrs}")
        if entry.kind == "file":
            digest = sha256_file(destination)
            expected = expected_file_hash(entry, artifacts)
            if digest != expected:
                fail(f"{path}: content hash mismatch: {digest} != {expected}")
        if entry.kind == "symlink":
            target = os.readlink(destination)
            if target != entry.content:
                fail(f"{path}: symlink mismatch: {target} != {entry.content}")
            logical_target = str(PurePosixPath(entry.path).parent / target)
            resolved = stage_path(root, logical_target)
            if not resolved.exists():
                fail(f"{path}: broken symlink: {target}")
    verify_static(stage_path(root, "/usr/bin/tinfoil-initrd"))


def align4(value: int) -> int:
    return (value + 3) & ~3


def cpio_record(name: str, ino: int, mode: int, uid: int, gid: int, nlink: int, data: bytes) -> bytes:
    name_data = name.encode() + b"\0"
    fields = (ino, mode, uid, gid, nlink, 0, len(data), 0, 0, 0, 0, len(name_data), 0)
    if any(value < 0 or value > UINT32_MAX for value in fields):
        fail(f"newc field overflow for {name}")
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    record = header + name_data
    record += b"\0" * (align4(len(record)) - len(record))
    record += data
    record += b"\0" * (align4(len(record)) - len(record))
    return record


def open_output_parent(output: Path) -> tuple[int, str]:
    normalized = Path(os.path.abspath(output))
    if normalized == Path("/"):
        fail("archive output must name a file")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    descriptor = os.open("/", directory_flags)
    try:
        for component in normalized.parts[1:-1]:
            try:
                child = os.open(component, directory_flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o755, dir_fd=descriptor)
                child = os.open(component, directory_flags, dir_fd=descriptor)
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    fail(f"archive output parent is not a real directory: {normalized.parent}")
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor, normalized.name
    except Exception:
        os.close(descriptor)
        raise


def write_output(output: Path, data: bytes) -> None:
    parent_descriptor, output_name = open_output_parent(output)
    temporary_name = f".{output_name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        try:
            metadata = os.stat(output_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and not stat.S_ISREG(metadata.st_mode):
            fail(f"archive output is not a regular file: {output}")
        descriptor = os.open(temporary_name, flags, 0o644, dir_fd=parent_descriptor)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as destination:
                destination.write(data)
            os.fchmod(descriptor, 0o644)
            os.utime(descriptor, (0, 0))
        finally:
            os.close(descriptor)
        os.replace(temporary_name, output_name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)


def write_archive(output: Path, root: Path, entries: dict[str, Entry], artifacts: dict[str, Artifact]) -> None:
    verify_stage(root, entries, artifacts)
    archive = bytearray()
    for ino, entry in enumerate(sorted(entries.values(), key=lambda item: item.path), 1):
        name = entry.path.removeprefix("/")
        if entry.kind == "dir":
            mode = stat.S_IFDIR | entry.mode
            data = b""
            nlink = 2
        elif entry.kind == "file":
            mode = stat.S_IFREG | entry.mode
            data = stage_path(root, entry.path).read_bytes()
            nlink = 1
        else:
            mode = stat.S_IFLNK | entry.mode
            data = entry.content.encode()
            nlink = 1
        archive.extend(cpio_record(name, ino, mode, entry.uid, entry.gid, nlink, data))
    archive.extend(cpio_record("TRAILER!!!", len(entries) + 1, 0, 0, 0, 1, b""))
    archive.extend(b"\0" * ((512 - len(archive) % 512) % 512))
    write_output(output, archive)


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
    trailer_seen = False
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        if header[:6] != b"070701":
            if not any(data[offset:]):
                break
            fail(f"invalid newc magic at offset {offset}")
        raw_fields = [header[index:index + 8] for index in range(6, 110, 8)]
        values = [int(field, 16) for field in raw_fields]
        if raw_fields != [f"{value:08x}".encode() for value in values]:
            fail(f"non-canonical newc field encoding at offset {offset}")
        ino, mode, uid, gid, nlink, mtime, size, devmajor, devminor, rdevmajor, rdevminor, namesize, check = values
        offset += 110
        name_data = data[offset:offset + namesize]
        if len(name_data) != namesize or namesize == 0 or not name_data.endswith(b"\0") or b"\0" in name_data[:-1]:
            fail("invalid newc filename")
        name = name_data[:-1].decode()
        name_end = offset + namesize
        padded_name_end = align4(name_end)
        if padded_name_end > len(data) or any(data[name_end:padded_name_end]):
            fail(f"non-zero or truncated newc filename padding for {name}")
        offset = padded_name_end
        content = data[offset:offset + size]
        if len(content) != size:
            fail(f"truncated newc data for {name}")
        content_end = offset + size
        padded_content_end = align4(content_end)
        if padded_content_end > len(data) or any(data[content_end:padded_content_end]):
            fail(f"non-zero or truncated newc data padding for {name}")
        offset = padded_content_end
        if name == "TRAILER!!!":
            if (
                ino != len(entries) + 1 or mode != 0 or uid != 0 or gid != 0 or nlink != 1
                or mtime != 0 or size != 0
                or any((devmajor, devminor, rdevmajor, rdevminor, check))
            ):
                fail("non-canonical newc trailer")
            expected_size = (offset + 511) & ~511
            if len(data) != expected_size or any(data[offset:]):
                fail("non-canonical data after newc trailer")
            trailer_seen = True
            break
        pure = PurePosixPath(name)
        if not name or pure.is_absolute() or ".." in pure.parts or str(pure) != name:
            fail(f"invalid archive path: {name}")
        path = "/" + name
        if path in entries:
            fail(f"duplicate archive path: {path}")
        entries[path] = (ino, mode, uid, gid, nlink, mtime, devmajor, devminor, rdevmajor, rdevminor, check, content)
        order.append(path)
    if not trailer_seen:
        fail("newc archive is missing its trailer")
    return entries, order


def verify_archive(archive: Path, entries: dict[str, Entry], artifacts: dict[str, Artifact]) -> None:
    result = subprocess.run(["zstd", "-q", "-d", "-c", str(archive)], capture_output=True, check=True)
    actual, order = parse_archive(result.stdout)
    if set(actual) != set(entries):
        missing = sorted(set(entries) - set(actual))
        unexpected = sorted(set(actual) - set(entries))
        fail(f"archive path mismatch; missing={missing}; unexpected={unexpected}")
    expected_order = sorted(entries)
    if order != expected_order:
        fail(f"archive path order mismatch: {order} != {expected_order}")
    for path, entry in entries.items():
        ino, mode, uid, gid, nlink, mtime, devmajor, devminor, rdevmajor, rdevminor, check, content = actual[path]
        expected_ino = expected_order.index(path) + 1
        expected_nlink = 2 if entry.kind == "dir" else 1
        if ino != expected_ino or nlink != expected_nlink:
            fail(f"{path}: archive inode/link metadata mismatch")
        kind = stat.S_IFMT(mode)
        expected_kind = {"dir": stat.S_IFDIR, "file": stat.S_IFREG, "symlink": stat.S_IFLNK}[entry.kind]
        if kind != expected_kind or stat.S_IMODE(mode) != entry.mode:
            fail(f"{path}: archive type/mode mismatch")
        if uid != entry.uid or gid != entry.gid:
            fail(f"{path}: archive ownership mismatch")
        if mtime != 0 or any((devmajor, devminor, rdevmajor, rdevminor, check)):
            fail(f"{path}: archive has non-deterministic metadata")
        if entry.kind == "dir" and content:
            fail(f"{path}: archive directory has data")
        if entry.kind == "symlink" and content.decode() != entry.content:
            fail(f"{path}: archive symlink target mismatch")
        if entry.kind == "file":
            expected = expected_file_hash(entry, artifacts)
            actual_hash = sha256_bytes(content)
            if actual_hash != expected:
                fail(f"{path}: archive file hash mismatch: {actual_hash} != {expected}")


def load(args):
    entries = parse_manifest(args.manifest)
    artifacts = parse_artifacts(args.artifacts)
    locks = parse_artifact_locks(args.artifact_lock)
    verify_artifact_locks(entries, artifacts, locks)
    return entries, artifacts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("stage", "verify-stage", "archive", "compress", "verify-archive"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--artifact-lock", type=Path, required=True)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--input", type=Path)
    args = parser.parse_args()
    entries, artifacts = load(args)
    if args.command == "stage":
        if args.stage is None:
            parser.error("stage requires --stage")
        create_stage(args.stage, entries, artifacts)
        verify_stage(args.stage, entries, artifacts)
    elif args.command == "verify-stage":
        if args.stage is None:
            parser.error("verify-stage requires --stage")
        verify_stage(args.stage, entries, artifacts)
    elif args.command == "archive":
        if args.stage is None or args.output is None:
            parser.error("archive requires --stage and --output")
        write_archive(args.output, args.stage, entries, artifacts)
    elif args.command == "compress":
        if args.input is None or args.output is None:
            parser.error("compress requires --input and --output")
        compress_archive(args.input, args.output)
    else:
        if args.archive is None:
            parser.error("verify-archive requires --archive")
        verify_archive(args.archive, entries, artifacts)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"initrd-manifest: {error}", file=sys.stderr)
        sys.exit(1)
