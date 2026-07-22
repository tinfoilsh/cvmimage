#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

try:
    from scripts.runtime_archive import (
        ArchiveError,
        _entry_type,
        _inspect_archive,
        _load_source_lock,
        _open_output_parent,
        _reject_duplicate_keys,
        validate_source_ids,
    )
except ModuleNotFoundError:
    from runtime_archive import (
        ArchiveError,
        _entry_type,
        _inspect_archive,
        _load_source_lock,
        _open_output_parent,
        _reject_duplicate_keys,
        validate_source_ids,
    )


TARGET = "//image:runtime-package-inputs-manifest"


def _bazel(workspace, output_root, *args):
    if not args:
        raise ArchiveError("Bazel command is missing")
    command = [
        os.environ.get("BAZEL", "bazel"),
        f"--output_user_root={output_root}",
        "--batch",
        args[0],
        "--symlink_prefix=/",
        "--lockfile_mode=error",
        *args[1:],
    ]
    try:
        result = subprocess.run(
            command,
            cwd=workspace,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or str(error)).strip()
        raise ArchiveError(f"Bazel {args[0]} failed: {detail[-4000:]}") from error
    return result.stdout.strip()


def _resolve(workspace, output_root):
    _bazel(workspace, output_root, "build", TARGET)
    outputs = _bazel(workspace, output_root, "cquery", "--output=files", TARGET).splitlines()
    manifests = [path for path in outputs if path.endswith("runtime-package-inputs.tsv")]
    if len(manifests) != 1:
        raise ArchiveError("expected exactly one package input manifest")
    execution_root = Path(_bazel(workspace, output_root, "info", "execution_root"))
    result = {}
    for line in (execution_root / manifests[0]).read_text(encoding="utf-8").splitlines():
        source_id, separator, relative = line.partition("\t")
        if not separator or source_id in result:
            raise ArchiveError("invalid or duplicate package input manifest entry")
        result[source_id] = execution_root / relative
    return result


def _same_bytes(left, right):
    with left.open("rb") as first, right.open("rb") as second:
        while True:
            a = first.read(1024 * 1024)
            b = second.read(1024 * 1024)
            if a != b:
                return False
            if not a:
                return True


def _entry_lock(path, member, data):
    entry = {
        "path": path,
        "type": _entry_type(member),
        "mode": f"{member.mode & 0o7777:04o}",
        "uid": member.uid,
        "gid": member.gid,
        "xattrs": {},
    }
    xattr_keys = [key for key in member.pax_headers if "xattr" in key.lower()]
    if xattr_keys:
        raise ArchiveError(f"package member has unsupported xattrs: {path}: {xattr_keys}")
    if member.isfile():
        entry["size"] = len(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()
    else:
        entry["target"] = member.linkname
    return entry


def _load_package_ids(path):
    try:
        document = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ArchiveError(f"cannot read runtime package lock: {error}") from error
    if not isinstance(document, dict) or set(document) != {"packages", "version"}:
        raise ArchiveError("runtime package lock must contain only packages and version")
    if type(document["version"]) is not int or document["version"] != 1:
        raise ArchiveError("unsupported runtime package lock version")
    packages = document["packages"]
    if not isinstance(packages, list) or not packages:
        raise ArchiveError("runtime package lock packages must be a non-empty list")
    package_ids = set()
    for package in packages:
        if not isinstance(package, dict):
            raise ArchiveError("runtime package lock entry must be an object")
        name = package.get("name")
        version = package.get("version")
        architecture = package.get("arch")
        source_id = package.get("key")
        if not all(isinstance(value, str) and value for value in (name, version, architecture, source_id)):
            raise ArchiveError("runtime package identity fields must be non-empty strings")
        expected = (
            name.replace("+", "-p-")
            + "_"
            + version.replace(":", "-").replace("+", "-p-")
            + "_"
            + architecture
        )
        if source_id != expected:
            raise ArchiveError(f"runtime package key does not match its identity: {source_id}")
        if source_id in package_ids:
            raise ArchiveError(f"duplicate runtime package identity: {source_id}")
        package_ids.add(source_id)
    return package_ids


def _regenerate(lock_path, package_lock_path, resolved):
    source_ids = sorted(resolved)
    validate_source_ids(lock_path, source_ids)
    package_ids = _load_package_ids(package_lock_path)
    stale = sorted(set(source_ids) - package_ids)
    if stale:
        raise ArchiveError(f"package member IDs are stale or unknown: {stale}")
    generated = {"version": 1, "sources": {}}
    for source_id in source_ids:
        _, _, locked, package_data = _load_source_lock(lock_path, source_id)
        if not package_data:
            raise ArchiveError(f"source is not fixed package-data mode: {source_id}")
        entries = _inspect_archive(resolved[source_id], "tar", package_data=True)
        files = []
        for path in sorted(locked):
            if path not in entries:
                raise ArchiveError(f"selected package member is missing: {source_id}: {path}")
            member, data = entries[path]
            if _entry_type(member) not in ("file", "symlink"):
                raise ArchiveError(f"unsupported selected package member: {source_id}: {path}")
            files.append(_entry_lock(path, member, data))
        generated["sources"][source_id] = {
            "kind": "tar",
            "package_data": True,
            "files": files,
        }
    return (json.dumps(generated, indent=2, sort_keys=True) + "\n").encode()


def _atomic_replace(path, data):
    parent_fd, output_name = _open_output_parent(path)
    temporary = None
    try:
        try:
            existing = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode):
                raise ArchiveError("existing package member lock must be a regular file")
        except FileNotFoundError:
            pass
        for _ in range(32):
            temporary = ".package-members-" + secrets.token_hex(16)
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                break
            except FileExistsError:
                temporary = None
        else:
            raise ArchiveError("cannot create package member lock temporary file")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, output_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def update(workspace, lock_path, package_lock_path=None, check=False, resolver=_resolve):
    workspace = Path(workspace).resolve()
    lock_path = Path(os.path.abspath(lock_path))
    if package_lock_path is None:
        package_lock_path = workspace / "image/runtime-packages.lock.json"
    package_lock_path = Path(os.path.abspath(package_lock_path))
    with tempfile.TemporaryDirectory(prefix="runtime-package-members-") as temporary:
        temporary = Path(temporary)
        first = resolver(workspace, temporary / "first")
        second = resolver(workspace, temporary / "second")
        if set(first) != set(second):
            raise ArchiveError("package input declarations differ between resolutions")
        for source_id in sorted(first):
            if not _same_bytes(first[source_id], second[source_id]):
                raise ArchiveError(f"package data is not reproducible: {source_id}")
        first_lock = _regenerate(lock_path, package_lock_path, first)
        second_lock = _regenerate(lock_path, package_lock_path, second)
        if first_lock != second_lock:
            raise ArchiveError("package member lock is not reproducible")
    current = lock_path.read_bytes()
    if current == first_lock:
        return
    if check:
        raise ArchiveError("runtime package member lock is stale")
    _atomic_replace(lock_path, first_lock)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--workspace", default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--lock",
        default=Path(__file__).resolve().parents[1] / "image/runtime-package-members.lock.json",
    )
    parser.add_argument("--package-lock")
    args = parser.parse_args()
    try:
        update(args.workspace, args.lock, args.package_lock, args.check)
    except (ArchiveError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"update_runtime_package_members.py: {error}\n")


if __name__ == "__main__":
    main()
