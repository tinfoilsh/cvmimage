#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath


REQUIRED_SOURCE_IDS = {
    "docker-static",
    "libnvidia-cfg1",
    "libnvidia-compute",
    "libnvidia-container-tools",
    "libnvidia-container1",
    "libnvidia-gpucomp",
    "libnvidia-nscq",
    "nvidia-container-toolkit",
    "nvidia-container-toolkit-base",
    "nvidia-fabricmanager",
    "nvidia-firmware",
    "nvidia-persistenced",
}
DOCKER_MEMBERS = {
    "docker/containerd",
    "docker/containerd-shim-runc-v2",
    "docker/dockerd",
    "docker/runc",
}
FORBIDDEN_SOURCE_FRAGMENTS = (
    "decode",
    "encode",
    "egl",
    "libnvidia-gl",
    "kernel-common",
    "kernel-module",
    "nvidia-smi",
    "tdx",
)
FORBIDDEN_PATHS = {
    "usr/bin/docker",
    "usr/bin/docker-init",
    "usr/bin/docker-proxy",
    "usr/bin/ctr",
    "usr/bin/nvidia-debugdump",
    "usr/bin/nvidia-fabricmanager-start.sh",
    "usr/bin/nvidia-smi",
    "usr/bin/nvswitch-audit",
}
FORBIDDEN_PATH_FRAGMENTS = ("cudadebugger", "opticalflow")
CONTROL_DEPENDENCY_EXCEPTIONS = {
    "nvidia-persistenced": {
        "adduser": "account creation is supplied by the fixed rootfs identity policy; package maintainer scripts are not used",
    },
}
DEPENDENCY_RE = re.compile(
    r"^([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9][a-z0-9-]*)?"
    r"(?:\s+\((<<|<=|=|>=|>>)\s+(\S+)\))?$"
)


class LockError(Exception):
    pass


def fail(message):
    raise LockError(message)


def load_lock(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def canonical_bytes(data):
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()


def clean_path(value):
    if not isinstance(value, str) or not value or value.startswith("/"):
        fail(f"invalid relative path: {value!r}")
    path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in path.parts):
        fail(f"non-canonical path: {value}")
    return value


def require_sorted_unique(values, label):
    if values != sorted(set(values)):
        fail(f"{label} must be sorted and unique")


def validate_lock(data, require_generated=True):
    if set(data) != {"architecture", "sources", "version"}:
        fail("top-level keys must be architecture, sources, and version")
    if data["version"] != 1 or data["architecture"] != "amd64":
        fail("unsupported source lock version or architecture")
    sources = data["sources"]
    if not isinstance(sources, list):
        fail("sources must be a list")
    ids = [source.get("id") for source in sources]
    require_sorted_unique(ids, "source ids")
    if set(ids) != REQUIRED_SOURCE_IDS:
        fail(f"source ids differ: {sorted(set(ids) ^ REQUIRED_SOURCE_IDS)}")
    for source in sources:
        validate_source(source, require_generated)


def validate_source(source, require_generated):
    source_id = source["id"]
    if any(fragment in source_id for fragment in FORBIDDEN_SOURCE_FRAGMENTS):
        fail(f"forbidden source: {source_id}")
    url = source.get("url")
    digest = source.get("sha256")
    if not isinstance(url, str) or not url.startswith("https://"):
        fail(f"source URL must use HTTPS: {source_id}")
    if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        fail(f"invalid SHA256: {source_id}")
    kind = source.get("kind")
    if kind == "tar":
        if set(source) - {"files", "id", "kind", "members", "sha256", "url"}:
            fail(f"unexpected tar keys: {source_id}")
        members = source.get("members")
        if set(members or []) != DOCKER_MEMBERS or len(members or []) != len(DOCKER_MEMBERS):
            fail("Docker source must select exactly four runtime binaries")
        require_sorted_unique(members, "Docker members")
    elif kind == "deb":
        allowed = {
            "architecture", "complete_directories", "control", "control_dependency_exceptions",
            "files", "id", "kind", "package", "paths", "sha256", "url", "version",
        }
        if set(source) - allowed:
            fail(f"unexpected deb keys: {source_id}")
        for key in ("architecture", "package", "version"):
            if not isinstance(source.get(key), str) or not source[key]:
                fail(f"missing {key}: {source_id}")
        if source["architecture"] != "amd64":
            fail(f"wrong architecture: {source_id}")
        paths = source.get("paths", [])
        directories = source.get("complete_directories", [])
        require_sorted_unique(paths, f"{source_id} paths")
        require_sorted_unique(directories, f"{source_id} complete directories")
        for path in paths:
            clean_path(path)
            if (
                path in FORBIDDEN_PATHS
                or path.startswith("usr/share/doc/")
                or any(fragment in path for fragment in FORBIDDEN_PATH_FRAGMENTS)
            ):
                fail(f"forbidden runtime path: {path}")
        for directory in directories:
            clean_path(directory.rstrip("/"))
            if not directory.endswith("/"):
                fail(f"complete directory must end in slash: {directory}")
        if source_id == "nvidia-fabricmanager" and directories != ["usr/share/nvidia/nvswitch/"]:
            fail("Fabric Manager must include the complete vendor topology directory")
        if source.get("control_dependency_exceptions", {}) != CONTROL_DEPENDENCY_EXCEPTIONS.get(source_id, {}):
            fail(f"unexpected control dependency exceptions: {source_id}")
    else:
        fail(f"unsupported source kind: {kind}")
    if require_generated:
        files = source.get("files")
        if not isinstance(files, list) or not files:
            fail(f"missing generated file metadata: {source_id}")
        file_paths = [entry.get("path") for entry in files]
        require_sorted_unique(file_paths, f"{source_id} generated files")
        for entry in files:
            validate_file_entry(entry)
        if kind == "tar":
            if file_paths != members:
                fail(f"generated Docker files differ from selected members: {source_id}")
        else:
            control = source.get("control")
            if not isinstance(control, dict) or set(control) != {
                "architecture", "depends", "package", "pre_depends", "version",
            }:
                fail(f"invalid generated control metadata: {source_id}")
            for key, value in control.items():
                if not isinstance(value, str):
                    fail(f"invalid generated control {key}: {source_id}")
            for key in ("architecture", "package", "version"):
                if control[key] != source[key]:
                    fail(f"generated control {key} mismatch: {source_id}")
            selected = set(paths)
            generated = set(file_paths)
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
                fail(
                    f"generated files differ from selected payload for {source_id}: "
                    f"missing={missing}, unexpected={unexpected}, empty_directories={empty_directories}"
                )
        if source_id == "nvidia-fabricmanager":
            topology = [path for path in file_paths if path.startswith("usr/share/nvidia/nvswitch/")]
            if len(topology) < 2 or "usr/share/nvidia/nvswitch/fabricmanager.cfg" not in topology:
                fail("Fabric Manager topology metadata is incomplete")


def validate_file_entry(entry):
    if not isinstance(entry, dict) or set(entry) not in (
        {"mode", "path", "sha256", "size", "type"},
        {"mode", "path", "target", "type"},
    ):
        fail(f"invalid generated file entry: {entry!r}")
    clean_path(entry["path"])
    if entry["path"] in FORBIDDEN_PATHS or any(
        fragment in entry["path"] for fragment in FORBIDDEN_PATH_FRAGMENTS
    ):
        fail(f"forbidden generated path: {entry['path']}")
    if entry["type"] == "file":
        digest = entry["sha256"]
        size = entry["size"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            fail(f"invalid generated regular file: {entry['path']}")
    elif entry["type"] == "symlink":
        if not isinstance(entry["target"], str) or not entry["target"]:
            fail(f"invalid generated symlink: {entry['path']}")
    else:
        fail(f"unsupported generated file type: {entry['path']}")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(source, directory):
    destination = directory / source["url"].rsplit("/", 1)[-1]
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with urllib.request.urlopen(source["url"], timeout=120) as response, open(temporary, "xb") as output:
        shutil.copyfileobj(response, output)
    if sha256_file(temporary) != source["sha256"]:
        temporary.unlink()
        fail(f"archive hash mismatch: {source['id']}")
    os.replace(temporary, destination)
    return destination


def regular_file_entry(path, mode, content):
    return {
        "mode": f"{mode:04o}",
        "path": path,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "type": "file",
    }


def canonicalize_tar(source, archive):
    with tarfile.open(archive, "r:gz") as bundle:
        members = {member.name.rstrip("/"): member for member in bundle.getmembers()}
        files = []
        for name in source["members"]:
            member = members.get(name)
            if member is None or not member.isfile():
                fail(f"missing Docker member: {name}")
            extracted = bundle.extractfile(member)
            if extracted is None:
                fail(f"cannot read Docker member: {name}")
            content = extracted.read()
            files.append(regular_file_entry(name, member.mode, content))
    source["files"] = files


def control_field(archive, field):
    result = subprocess.run(
        ["dpkg-deb", "--field", archive, field],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode not in (0, 2):
        fail(f"dpkg-deb failed for {archive}: {result.stderr.strip()}")
    return " ".join(result.stdout.split())


def normalized_tar_path(name):
    while name.startswith("./"):
        name = name[2:]
    if not name or name == ".":
        return None
    return clean_path(name.rstrip("/"))


def canonicalize_deb(source, archive):
    control = {
        "architecture": control_field(archive, "Architecture"),
        "depends": control_field(archive, "Depends"),
        "package": control_field(archive, "Package"),
        "pre_depends": control_field(archive, "Pre-Depends"),
        "version": control_field(archive, "Version"),
    }
    for key in ("architecture", "package", "version"):
        if control[key] != source[key]:
            fail(f"control {key} mismatch for {source['id']}: {control[key]!r}")
    requested = set(source.get("paths", []))
    complete_directories = source.get("complete_directories", [])
    found = {}
    process = subprocess.Popen(
        ["dpkg-deb", "--fsys-tarfile", archive],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as bundle:
            for member in bundle:
                path = normalized_tar_path(member.name)
                if path is None:
                    continue
                selected = path in requested or any(
                    path.startswith(directory) for directory in complete_directories
                )
                if not selected or member.isdir():
                    continue
                if member.isfile():
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        fail(f"cannot read selected payload: {path}")
                    found[path] = regular_file_entry(path, member.mode, extracted.read())
                elif member.issym():
                    target = member.linkname
                    if not target or target.startswith("/") or ".." in PurePosixPath(target).parts:
                        fail(f"unsafe selected symlink target: {path} -> {target}")
                    found[path] = {
                        "mode": f"{member.mode:04o}",
                        "path": path,
                        "target": target,
                        "type": "symlink",
                    }
                else:
                    fail(f"selected payload has unsupported tar type: {path}")
        stderr = process.stderr.read().decode(errors="replace")
        if process.wait() != 0:
            fail(f"dpkg-deb payload stream failed for {source['id']}: {stderr.strip()}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    missing = sorted(requested - set(found))
    if missing:
        fail(f"missing selected paths for {source['id']}: {missing}")
    for directory in complete_directories:
        if not any(path.startswith(directory) for path in found):
            fail(f"complete directory is empty: {directory}")
    source["control"] = control
    source["files"] = [found[path] for path in sorted(found)]


def canonicalize(data, download_root):
    validate_lock(data, require_generated=False)
    for source in data["sources"]:
        source.pop("control", None)
        source.pop("files", None)
        source_dir = download_root / source["id"]
        source_dir.mkdir()
        archive = download(source, source_dir)
        if source["kind"] == "tar":
            canonicalize_tar(source, archive)
        else:
            canonicalize_deb(source, archive)
    validate_lock(data, require_generated=True)
    return data


def dependency_groups(value):
    groups = []
    for group in value.split(","):
        alternatives = []
        for alternative in group.split("|"):
            alternative = alternative.strip()
            if not alternative:
                continue
            match = DEPENDENCY_RE.fullmatch(alternative)
            if match is None:
                fail(f"unsupported control dependency: {alternative}")
            alternatives.append(match.groups())
        if alternatives:
            groups.append(alternatives)
    return groups


def validate_control_dependencies(source_lock, package_lock):
    sources = load_lock(source_lock)
    validate_lock(sources, require_generated=True)
    packages = load_lock(package_lock)
    if packages.get("version") != 1 or not isinstance(packages.get("packages"), list):
        fail("unsupported Ubuntu package lock")
    available = {}
    for package in packages["packages"]:
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            fail("invalid Ubuntu package lock entry")
        if name in available:
            fail(f"duplicate locked package: {name}")
        available[name] = version
    for source in sources["sources"]:
        if source["kind"] != "deb":
            continue
        name = source["package"]
        if name in available:
            fail(f"duplicate locked package: {name}")
        available[name] = source["version"]
    for source in sources["sources"]:
        if source["kind"] != "deb":
            continue
        exceptions = source.get("control_dependency_exceptions", {})
        for field in ("depends", "pre_depends"):
            for alternatives in dependency_groups(source["control"][field]):
                satisfied = False
                labels = []
                for name, operator, required_version in alternatives:
                    label = name if operator is None else f"{name} ({operator} {required_version})"
                    labels.append(label)
                    if name in exceptions:
                        satisfied = True
                        break
                    locked_version = available.get(name)
                    if locked_version is None:
                        continue
                    if operator is None:
                        satisfied = True
                        break
                    comparison = subprocess.run(
                        ["dpkg", "--compare-versions", locked_version, operator, required_version],
                        check=False,
                    )
                    if comparison.returncode == 0:
                        satisfied = True
                        break
                    if comparison.returncode != 1:
                        fail(f"dpkg rejected control dependency: {label}")
                if not satisfied:
                    fail(f"unresolved control dependency for {source['id']}: {' | '.join(labels)}")


def atomic_replace(path, content):
    destination = Path(path)
    temporary = destination.with_name(f".{destination.name}.new-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("lock")
    canonicalize_parser = subparsers.add_parser("canonicalize")
    canonicalize_parser.add_argument("lock")
    canonicalize_parser.add_argument("output")
    canonicalize_parser.add_argument("download_root")
    dependencies_parser = subparsers.add_parser("validate-dependencies")
    dependencies_parser.add_argument("source_lock")
    dependencies_parser.add_argument("package_lock")
    atomic_parser = subparsers.add_parser("atomic-replace")
    atomic_parser.add_argument("source")
    atomic_parser.add_argument("destination")
    args = parser.parse_args()
    try:
        if args.command == "validate":
            validate_lock(load_lock(args.lock), require_generated=True)
        elif args.command == "canonicalize":
            data = canonicalize(load_lock(args.lock), Path(args.download_root))
            Path(args.output).write_bytes(canonical_bytes(data))
        elif args.command == "validate-dependencies":
            validate_control_dependencies(args.source_lock, args.package_lock)
        else:
            atomic_replace(args.destination, Path(args.source).read_bytes())
    except (LockError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as error:
        print(f"runtime source lock: {error}", file=os.sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
