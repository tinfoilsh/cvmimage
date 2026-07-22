#!/usr/bin/env python3
import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import secrets
import stat
import tarfile
from pathlib import Path, PurePosixPath


class ArchiveError(Exception):
    pass


def _exact_object(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        raise ArchiveError(f"{label} must contain exactly: {', '.join(sorted(keys))}")


def _lower_sha256(value, label):
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ArchiveError(f"{label} is invalid")
    return value


def _canonical_path(raw, allow_debian_prefix=False):
    if not isinstance(raw, str) or not raw or "\\" in raw or raw.startswith("/"):
        raise ArchiveError(f"non-canonical archive path: {raw!r}")
    path = raw[:-1] if raw.endswith("/") else raw
    parts = path.split("/")
    if parts and parts[0] == ".":
        if not allow_debian_prefix:
            raise ArchiveError(f"non-canonical archive path: {raw!r}")
        parts = parts[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ArchiveError(f"non-canonical archive path: {raw!r}")
    return "/".join(parts)


def _safe_symlink_target(path, target):
    if not isinstance(target, str) or not target or "\\" in target or target.startswith("/"):
        raise ArchiveError(f"unsafe symlink target for {path}: {target!r}")
    depth = 0
    for part in PurePosixPath(path).parent.joinpath(target).parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                raise ArchiveError(f"symlink target escapes archive root: {path} -> {target}")
        else:
            depth += 1


def _load_source_lock(path):
    try:
        source = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArchiveError(f"cannot read source lock: {error}") from error
    if not isinstance(source, dict):
        raise ArchiveError("source lock must be an object")
    kind = source.get("kind")
    if kind not in ("tar", "deb"):
        raise ArchiveError("source lock kind must be tar or deb")
    if kind == "tar":
        _exact_object(source, {"files", "id", "kind", "members", "sha256", "url"}, "tar source lock")
    else:
        required = {"architecture", "control", "files", "id", "kind", "package", "paths", "sha256", "url", "version"}
        valid_shapes = (
            required,
            required | {"complete_directories"},
            required | {"control_dependency_exceptions"},
            required | {"complete_directories", "control_dependency_exceptions"},
        )
        if set(source) not in valid_shapes:
            raise ArchiveError("Debian source lock has an invalid object shape")
    source_id = source["id"]
    if (
        not isinstance(source_id, str)
        or not source_id
        or source_id.startswith("-")
        or source_id.endswith("-")
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in source_id)
    ):
        raise ArchiveError("source lock id is invalid")
    if not isinstance(source["url"], str) or not source["url"].startswith("https://"):
        raise ArchiveError("source lock URL must use HTTPS")
    archive_sha256 = _lower_sha256(source["sha256"], "source lock archive SHA256")
    files = source["files"]
    if not isinstance(files, list) or not files:
        raise ArchiveError("source lock files must be a non-empty list")
    locked = {}
    for entry in files:
        if not isinstance(entry, dict):
            raise ArchiveError("source lock file entry must be an object")
        entry_type = entry.get("type")
        if entry_type == "file":
            _exact_object(entry, {"mode", "path", "sha256", "size", "type"}, "locked file entry")
        elif entry_type == "symlink":
            _exact_object(entry, {"mode", "path", "target", "type"}, "locked symlink entry")
        else:
            raise ArchiveError(f"unsupported locked type: {entry_type}")
        path = _canonical_path(entry["path"])
        if path != entry["path"]:
            raise ArchiveError(f"source lock path is not canonical: {entry['path']!r}")
        if path in locked:
            raise ArchiveError(f"duplicate source lock path: {path}")
        mode = entry["mode"]
        if not isinstance(mode, str) or len(mode) != 4 or any(c not in "01234567" for c in mode):
            raise ArchiveError(f"invalid locked mode for {path}: {mode!r}")
        if entry_type == "file":
            _lower_sha256(entry["sha256"], f"locked SHA256 for {path}")
            size = entry["size"]
            if type(size) is not int or size < 0:
                raise ArchiveError(f"invalid locked size for {path}")
        else:
            _safe_symlink_target(path, entry["target"])
        locked[path] = entry
    if kind == "tar":
        members = source["members"]
        if not isinstance(members, list) or members != list(locked):
            raise ArchiveError("tar source lock members must exactly match files")
    else:
        for key in ("architecture", "package", "version"):
            if not isinstance(source[key], str) or not source[key]:
                raise ArchiveError(f"Debian source lock {key} is invalid")
        _exact_object(source["control"], {"architecture", "depends", "package", "pre_depends", "version"}, "Debian control lock")
        if any(not isinstance(value, str) for value in source["control"].values()):
            raise ArchiveError("Debian control lock values must be strings")
        for key in ("architecture", "package", "version"):
            if source["control"][key] != source[key]:
                raise ArchiveError(f"Debian control lock {key} does not match source lock")
        paths = source["paths"]
        if (
            not isinstance(paths, list)
            or not paths
            or paths != sorted(set(paths))
            or any(_canonical_path(item) != item for item in paths)
        ):
            raise ArchiveError("Debian source lock paths are invalid")
        directories = source.get("complete_directories", [])
        if "complete_directories" in source:
            if not isinstance(directories, list) or not directories or directories != sorted(set(directories)):
                raise ArchiveError("Debian complete directories are invalid")
            for directory in directories:
                if not isinstance(directory, str) or not directory.endswith("/") or _canonical_path(directory) != directory[:-1]:
                    raise ArchiveError("Debian complete directories are invalid")
        if "control_dependency_exceptions" in source:
            exceptions = source["control_dependency_exceptions"]
            if not isinstance(exceptions, dict) or not exceptions or any(
                not isinstance(name, str) or not name or not isinstance(reason, str) or not reason
                for name, reason in exceptions.items()
            ):
                raise ArchiveError("Debian control dependency exceptions are invalid")
        selected = set(paths)
        generated = set(locked)
        missing = sorted(selected - generated)
        unexpected = sorted(
            path for path in generated
            if path not in selected and not any(path.startswith(directory) for directory in directories)
        )
        empty_directories = sorted(
            directory for directory in directories
            if not any(path.startswith(directory) for path in generated)
        )
        if missing or unexpected or empty_directories:
            raise ArchiveError(
                "Debian source lock files differ from selected payload: "
                f"missing={missing}, unexpected={unexpected}, empty_directories={empty_directories}"
            )
    return kind, archive_sha256, locked


def _ar_members(path):
    data = Path(path).read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise ArchiveError("invalid Debian ar archive header")
    offset = 8
    members = {}
    while offset < len(data):
        if offset + 60 > len(data):
            raise ArchiveError("truncated ar member header")
        header = data[offset:offset + 60]
        if header[58:60] != b"`\n":
            raise ArchiveError("invalid ar member header")
        try:
            name = header[:16].decode("ascii").strip().removesuffix("/")
            size_field = header[48:58].decode("ascii")
        except UnicodeDecodeError as error:
            raise ArchiveError("invalid ar member metadata") from error
        size_text = size_field.rstrip(" ")
        if not size_text or not size_text.isascii() or not size_text.isdecimal():
            raise ArchiveError("invalid ar member size")
        size = int(size_text, 10)
        if size < 0:
            raise ArchiveError("invalid ar member size")
        if not name or name.startswith("/") or name in members:
            raise ArchiveError(f"invalid or duplicate ar member: {name!r}")
        start = offset + 60
        end = start + size
        if end > len(data):
            raise ArchiveError(f"truncated ar member: {name}")
        members[name] = data[start:end]
        if size % 2:
            if end >= len(data) or data[end:end + 1] != b"\n":
                raise ArchiveError(f"missing or non-canonical ar padding for: {name}")
            offset = end + 1
        else:
            offset = end
    return members


def _decompress_tar(name, data):
    try:
        if name.endswith(".tar"):
            return data
        if name.endswith((".tar.gz", ".tgz")):
            return gzip.decompress(data)
        if name.endswith(".tar.bz2"):
            return bz2.decompress(data)
        if name.endswith((".tar.xz", ".tar.lzma")):
            return lzma.decompress(data)
        if name.endswith(".tar.zst"):
            from compression import zstd
            return zstd.decompress(data)
    except Exception as error:
        raise ArchiveError(f"cannot decompress {name}: {error}") from error
    raise ArchiveError(f"unsupported tar compression: {name}")


def _open_payload(archive, kind):
    if kind == "tar":
        return tarfile.open(archive, mode="r:*")
    members = _ar_members(archive)
    if members.get("debian-binary") != b"2.0\n":
        raise ArchiveError("Debian archive has an invalid debian-binary member")
    control_names = sorted(name for name in members if name.startswith("control.tar"))
    data_names = sorted(name for name in members if name.startswith("data.tar"))
    allowed_names = {"debian-binary"} | set(control_names) | set(data_names)
    if "_gpgbuilder" in members:
        allowed_names.add("_gpgbuilder")
    if len(control_names) != 1 or len(data_names) != 1 or set(members) != allowed_names:
        raise ArchiveError("Debian archive contains unexpected or duplicate payload members")
    payload = _decompress_tar(data_names[0], members[data_names[0]])
    return tarfile.open(fileobj=io.BytesIO(payload), mode="r:")


def _entry_type(member):
    if member.isfile():
        return "file"
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    return "unexpected"


def _inspect_archive(archive, kind):
    entries = {}
    with _open_payload(archive, kind) as payload:
        for member in payload.getmembers():
            if member.name in (".", "./"):
                if not member.isdir():
                    raise ArchiveError("archive root marker must be a directory")
                continue
            path = _canonical_path(member.name, allow_debian_prefix=(kind == "deb"))
            if path in entries:
                raise ArchiveError(f"duplicate normalized archive path: {path}")
            entry_type = _entry_type(member)
            if entry_type == "unexpected":
                raise ArchiveError(f"unexpected archive type for {path}")
            if entry_type == "symlink":
                _safe_symlink_target(path, member.linkname)
            entries[path] = (member, payload.extractfile(member) if entry_type == "file" else None)

        symlink_paths = {path for path, (member, _) in entries.items() if member.issym()}
        for path in entries:
            parent = PurePosixPath(path).parent
            while str(parent) != ".":
                if str(parent) in symlink_paths:
                    raise ArchiveError(f"archive entry has a symlink parent: {path}")
                parent = parent.parent

        materialized = {}
        for path, (member, stream) in entries.items():
            if member.isfile():
                if stream is None:
                    raise ArchiveError(f"cannot read archive member: {path}")
                materialized[path] = (member, stream.read())
            else:
                materialized[path] = (member, None)
        return materialized


def _verify_locked(entries, locked):
    selected = {}
    for path, expected in locked.items():
        if path not in entries:
            raise ArchiveError(f"locked member is missing: {path}")
        member, data = entries[path]
        actual_type = _entry_type(member)
        if actual_type != expected["type"]:
            raise ArchiveError(f"locked member type mismatch for {path}: {actual_type}")
        actual_mode = f"{stat.S_IMODE(member.mode):04o}"
        if actual_mode != expected["mode"]:
            raise ArchiveError(f"locked member mode mismatch for {path}: {actual_mode}")
        if actual_type == "file":
            if len(data) != expected["size"]:
                raise ArchiveError(f"locked member size mismatch for {path}")
            if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                raise ArchiveError(f"locked member SHA256 mismatch for {path}")
        elif member.linkname != expected["target"]:
            raise ArchiveError(f"locked symlink target mismatch for {path}")
        selected[path] = (member, data)
    return selected


def _open_output_parent(path):
    raw = os.fspath(path)
    if not raw or "\x00" in raw or raw.endswith("/"):
        raise ArchiveError("output path is empty or malformed")
    absolute = raw.startswith("/")
    parts = raw.split("/")[1:] if absolute else raw.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ArchiveError(f"output path contains an unsafe component: {raw}")
    name = parts[-1]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    current = os.open("/" if absolute else ".", flags)
    try:
        for component in parts[:-1]:
            following = os.open(component, flags | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
        return current, name
    except Exception:
        os.close(current)
        raise


def _write_output(path, selected):
    parent_fd, output_name = _open_output_parent(path)
    temporary_name = None
    try:
        try:
            existing = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode):
                raise ArchiveError("existing output must be a regular file")
        except FileNotFoundError:
            pass
        for _ in range(32):
            candidate = ".runtime-archive-" + secrets.token_hex(16)
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                temporary_name = candidate
                os.fchmod(temporary_fd, 0o644)
                break
            except FileExistsError:
                continue
        else:
            raise ArchiveError("cannot create an exclusive output temporary file")
        with os.fdopen(temporary_fd, "wb") as stream, tarfile.open(
            fileobj=stream,
            mode="w",
            format=tarfile.GNU_FORMAT,
        ) as result:
            for path in sorted(selected):
                source, data = selected[path]
                member = tarfile.TarInfo(path)
                member.mode = stat.S_IMODE(source.mode)
                member.uid = 0
                member.gid = 0
                member.uname = "root"
                member.gname = "root"
                member.mtime = 0
                if source.isfile():
                    member.type = tarfile.REGTYPE
                    member.size = len(data)
                    result.addfile(member, io.BytesIO(data))
                else:
                    member.type = tarfile.SYMTYPE
                    member.linkname = source.linkname
                    result.addfile(member)
        os.replace(temporary_name, output_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def extract_locked_archive(archive, source_lock, output):
    kind, archive_sha256, locked = _load_source_lock(source_lock)
    digest = hashlib.sha256()
    with Path(archive).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != archive_sha256:
        raise ArchiveError("source archive SHA256 does not match the lock")
    entries = _inspect_archive(archive, kind)
    _write_output(output, _verify_locked(entries, locked))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--source-lock", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        extract_locked_archive(args.archive, args.source_lock, args.output)
    except (ArchiveError, OSError, tarfile.TarError) as error:
        parser.exit(1, f"runtime_archive.py: {error}\n")


if __name__ == "__main__":
    main()
