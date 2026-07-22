#!/usr/bin/env python3

import argparse
import base64
import contextlib
import errno
import hashlib
import io
import json
import os
import re
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from scripts import rootfs_artifacts, rootfs_manifest


PACKAGE_IDS = tuple(sorted((
    "ca-certificates_20260223_amd64", "iproute2_6.19.0-1ubuntu1_amd64",
    "libbpf1_1-1.6.3-1ubuntu1_amd64", "libbsd0_0.12.2-2build2_amd64",
    "libc6_2.43-2ubuntu2_amd64", "libcap2_1-2.75-10ubuntu2_amd64",
    "libcom-err2_1.47.2-3ubuntu4_amd64", "libedit2_3.1-20251016-1_amd64",
    "libelf1t64_0.194-4_amd64", "libgcc-s1_16-20260322-1ubuntu1_amd64",
    "libgmp10_2-6.3.0-p-dfsg-5ubuntu2_amd64", "libgssapi-krb5-2_1.22.1-2ubuntu4_amd64",
    "libjansson4_2.14-2build4_amd64", "libk5crypto3_1.22.1-2ubuntu4_amd64",
    "libkeyutils1_1.6.3-6ubuntu3_amd64", "libkrb5-3_1.22.1-2ubuntu4_amd64",
    "libkrb5support0_1.22.1-2ubuntu4_amd64", "libmd0_1.1.0-2build4_amd64",
    "libmnl0_1.0.5-3build1_amd64", "libnftables1_1.1.6-1_amd64",
    "libnftnl11_1.3.1-1_amd64", "libpcre2-8-0_10.46-1build1_amd64",
    "libseccomp2_2.6.0-2ubuntu5_amd64", "libselinux1_3.9-4build1_amd64",
    "libssl3t64_3.5.5-1ubuntu3.2_amd64", "libstdc-p--p-6_16-20260322-1ubuntu1_amd64",
    "libtinfo6_6.6-p-20251231-1_amd64", "libtirpc-common_1.3.7-0.1_amd64",
    "libtirpc3t64_1.3.7-0.1_amd64", "libxml2-16_2.15.2-p-dfsg-0.1_amd64",
    "libxtables12_1.8.11-2ubuntu3_amd64", "libzstd1_1.5.7-p-dfsg-3_amd64",
    "nftables_1.1.6-1_amd64", "openssl_3.5.5-1ubuntu3.2_amd64",
    "zlib1g_1-1.3.dfsg-p-really1.3.1-1ubuntu3_amd64",
)))
VENDOR_IDS = (
    "docker-static", "libnvidia-cfg1", "libnvidia-compute", "libnvidia-container-tools",
    "libnvidia-container1", "libnvidia-gpucomp", "libnvidia-nscq",
    "nvidia-container-toolkit-base", "nvidia-fabricmanager", "nvidia-firmware",
    "nvidia-persistenced",
)
CONFIG_PATHS = (
    "etc/containerd/config.toml", "etc/docker/daemon.json", "etc/group", "etc/gshadow",
    "etc/hostname", "etc/hosts", "etc/nftables.conf", "etc/nsswitch.conf",
    "etc/nvidia-container-runtime/config.toml", "etc/passwd", "etc/resolv.conf", "etc/shadow",
)
SKELETON = ("/dev", "/proc", "/run", "/sys", "/tmp", "/var", "/var/tmp", "/mnt", "/mnt/ramdisk")
LINKS = {
    "/bin": "usr/bin", "/lib": "usr/lib", "/lib64": "usr/lib64", "/sbin": "usr/sbin",
    "/etc/mtab": "../proc/self/mounts", "/var/run": "/run",
}
FM_PATH = "/usr/share/nvidia/nvswitch/fabricmanager.cfg"
FM_BEFORE = b"FM_CMD_UNIX_SOCKET_PATH=\n"
FM_AFTER = b"FM_CMD_UNIX_SOCKET_PATH=/run/nvidia-fabricmanager/socket\n"
FM_INPUT = "068da67ec6430e912e727966031b66bddcf4a48988ec24a75d2fa1dd659058e8"
FM_OUTPUT = "89612c99a33dd7ccc00738c4897591c95a576ef2f289481523b64a780d1390d8"
EXCLUDED = "etc/nvidia-container-toolkit/nvidia-cdi-refresh.env"
FORBIDDEN_EXACT = {
    "/etc/ld.so.cache", "/etc/shells", "/usr/bin/docker-init", "/usr/bin/nvidia-smi",
    "/usr/bin/nvidia-container-runtime-hook", "/usr/sbin/ip6tables", "/usr/sbin/iptables",
    "/usr/sbin/iptables-nft", "/usr/sbin/ip6tables-nft", "/usr/sbin/xtables-nft-multi",
}
MODE = re.compile(r"[0-7]{4}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class AssemblyError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    mode: str
    digest: str = "-"
    link: str = "-"
    archive: Path | None = None
    member: str = ""
    source: Path | None = None
    replacement: bytes | None = None


def fail(message):
    raise AssemblyError(message)


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@contextlib.contextmanager
def checked_descriptor(path, expected_mode=None):
    path = Path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        sandbox = "/sandbox/" in str(Path.cwd())
        if error.errno != errno.ELOOP or not sandbox or path.is_absolute():
            fail(f"unsafe input path {path}: {error}")
        target = os.readlink(path)
        if not os.path.isabs(target):
            fail(f"unsafe Bazel input link {path}: target is not absolute")
        try:
            descriptor = os.open(target, flags)
        except OSError as target_error:
            fail(f"unsafe Bazel input target {path}: {target_error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or os.listxattr(descriptor):
            fail(f"input must be a single-linked xattr-free regular file: {path}")
        if expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode:
            fail(f"input mode differs from fixed contract: {path}")
        yield descriptor, before
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
        )
        if identity(before) != identity(after) or os.listxattr(descriptor):
            fail(f"input changed while being read: {path}")
    finally:
        os.close(descriptor)


def checked_bytes(path, expected_mode=None):
    with checked_descriptor(path, expected_mode) as (descriptor, _):
        with os.fdopen(os.dup(descriptor), "rb") as source:
            return source.read()


def load_json(path):
    try:
        return json.loads(checked_bytes(path).decode(), object_pairs_hook=json_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read lock {path}: {error}")


def canonical(path, absolute=False):
    if not isinstance(path, str) or not path or "\\" in path or "\0" in path:
        fail(f"invalid path: {path!r}")
    pure = PurePosixPath(path)
    if absolute != path.startswith("/") or ".." in pure.parts or "." in pure.parts or str(pure) != path:
        fail(f"non-canonical path: {path!r}")
    return path


def safe_link(path, target):
    if not target or "\\" in target or "\0" in target:
        fail(f"unsafe symlink: {path} -> {target!r}")
    base = PurePosixPath() if target.startswith("/") else PurePosixPath(path[1:]).parent
    depth = 0
    for part in base.joinpath(target.removeprefix("/")).parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                fail(f"symlink escapes rootfs: {path} -> {target}")
        elif part not in ("", "."):
            depth += 1


def lock_entries(files):
    if not isinstance(files, list) or not files:
        fail("locked member list must be non-empty")
    result = {}
    for raw in files:
        if not isinstance(raw, dict):
            fail("locked member must be an object")
        path = canonical(raw.get("path"))
        kind = raw.get("type")
        mode = raw.get("mode")
        if path in result or kind not in ("file", "symlink") or not isinstance(mode, str) or not MODE.fullmatch(mode):
            fail(f"invalid locked member: {path}")
        if kind == "file":
            digest, size, link = raw.get("sha256"), raw.get("size"), "-"
            if not isinstance(digest, str) or not SHA256.fullmatch(digest) or not isinstance(size, int) or isinstance(size, bool) or size < 0:
                fail(f"invalid locked file: {path}")
        else:
            digest, size, link = "-", 0, raw.get("target")
            if not isinstance(link, str):
                fail(f"invalid locked symlink: {path}")
            safe_link("/" + path, link)
        result[path] = (kind, mode, digest, size, link)
    return result


def authenticate_archive_consumption(descriptor, size, members, archive_offset):
    expected_offset = 0
    for member in members:
        if member.offset != expected_offset or member.offset_data != member.offset + tarfile.BLOCKSIZE:
            fail(f"non-canonical archive member layout: {member.name}")
        content_end = member.offset_data + member.size
        expected_offset = ((content_end + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
        padding = os.pread(descriptor, expected_offset - content_end, content_end)
        if padding != b"\0" * (expected_offset - content_end):
            fail(f"non-canonical archive member padding: {member.name}")
    if archive_offset != expected_offset:
        fail("member archive consumption differs from canonical layout")
    minimum_size = expected_offset + 2 * tarfile.BLOCKSIZE
    expected_size = ((minimum_size + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    if size != expected_size:
        fail("member archive length differs from canonical layout")
    trailer = os.pread(descriptor, size - expected_offset, expected_offset)
    if trailer != b"\0" * (size - expected_offset):
        fail("member archive has non-zero trailer padding")


def inspect_member_archive(path, locked, names="root"):
    result = {}
    try:
        with checked_descriptor(path) as (descriptor, metadata):
            with os.fdopen(os.dup(descriptor), "rb") as raw, tarfile.open(fileobj=raw, mode="r:") as archive:
                members = archive.getmembers()
                for member in members:
                    name = canonical(member.name)
                    if name in result or member.pax_headers or member.offset % 512:
                        fail(f"invalid or duplicate archive member: {name}")
                    if member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname != names or member.gname != names:
                        fail(f"non-canonical archive metadata: {name}")
                    if member.isfile():
                        kind, link = "file", "-"
                    elif member.issym():
                        kind, link = "symlink", member.linkname
                        safe_link("/" + name, link)
                    else:
                        fail(f"forbidden archive member type: {name}")
                    expected = locked.get(name)
                    if expected is None or (kind, f"{stat.S_IMODE(member.mode):04o}", link) != (expected[0], expected[1], expected[4]):
                        fail(f"archive member differs from lock: {name}")
                    if kind == "file":
                        stream = archive.extractfile(member)
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                        if (expected[3] is not None and member.size != expected[3]) or digest != expected[2]:
                            fail(f"archive member content differs from lock: {name}")
                    result[name] = member
                authenticate_archive_consumption(descriptor, metadata.st_size, members, archive.offset)
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot inspect member archive {path}: {error}")
    if set(result) != set(locked):
        fail(f"member archive inventory differs from lock: {path}")


def add(entries, entry):
    canonical(entry.path, True)
    if entry.path in entries:
        fail(f"duplicate rootfs destination: {entry.path}")
    for parent in PurePosixPath(entry.path).parents:
        if str(parent) in entries and entries[str(parent)].kind != "dir":
            fail(f"non-directory ancestor for {entry.path}: {parent}")
    if entry.kind == "symlink":
        safe_link(entry.path, entry.link)
    entries[entry.path] = entry


def mapped_vendor(source_id, path):
    if source_id == "docker-static":
        if not path.startswith("docker/") or path.count("/") != 1:
            fail(f"unexpected Docker member: {path}")
        return "/usr/bin/" + path.removeprefix("docker/")
    if source_id == "nvidia-firmware":
        if not path.startswith("lib/firmware/"):
            fail(f"unexpected firmware member: {path}")
        return "/usr/" + path
    return "/" + path


def transform_fabricmanager(content):
    if hashlib.sha256(content).hexdigest() != FM_INPUT or content.count(FM_BEFORE) != 1:
        fail("Fabric Manager input differs from fixed transform contract")
    transformed = content.replace(FM_BEFORE, FM_AFTER)
    if hashlib.sha256(transformed).hexdigest() != FM_OUTPUT:
        fail("Fabric Manager transformed hash differs from fixed contract")
    return transformed


def archive_entries(inputs, document, package):
    sources = document.get("sources")
    if package:
        if document.get("version") != 1 or not isinstance(sources, dict) or set(sources) != set(PACKAGE_IDS):
            fail("package lock source set differs from fixed contract")
        selected = [(source_id, sources[source_id]) for source_id in PACKAGE_IDS]
    else:
        if document.get("version") != 1 or not isinstance(sources, list):
            fail("vendor lock format differs from fixed contract")
        indexed = {source.get("id"): source for source in sources}
        expected = set(VENDOR_IDS) | {"nvidia-container-toolkit"}
        if len(indexed) != len(sources) or set(indexed) != expected:
            fail("vendor lock source set differs from fixed contract")
        selected = [(source_id, indexed[source_id]) for source_id in VENDOR_IDS]
    if tuple(source_id for source_id, _ in inputs) != (PACKAGE_IDS if package else VENDOR_IDS):
        fail("archive arguments differ from fixed source order")
    result = []
    for (source_id, archive_path), (_, source) in zip(inputs, selected, strict=True):
        locked = lock_entries(source.get("files"))
        inspect_member_archive(archive_path, locked)
        for path, (kind, mode, digest, _, link) in locked.items():
            if not package and source_id == "nvidia-container-toolkit-base" and path == EXCLUDED:
                continue
            destination = "/" + path if package else mapped_vendor(source_id, path)
            replacement = None
            if destination == FM_PATH:
                if digest != FM_INPUT or mode != "0644" or kind != "file":
                    fail("Fabric Manager input differs from fixed transform contract")
                with checked_descriptor(archive_path) as (descriptor, _):
                    with os.fdopen(os.dup(descriptor), "rb") as raw, tarfile.open(fileobj=raw, mode="r:") as archive:
                        content = archive.extractfile(archive.getmember(path)).read()
                replacement = transform_fabricmanager(content)
                digest = FM_OUTPUT
            result.append(Entry(destination, kind, mode, digest, link, Path(archive_path), path, replacement=replacement))
    return result


def runtime_entries(archive_path, manifest_path, lock_path):
    locked = rootfs_artifacts.parse_content(Path(lock_path), checked_bytes(lock_path).decode())
    manifest = rootfs_manifest.parse_content(Path(manifest_path), checked_bytes(manifest_path))
    archive_lock = {}
    for entry in locked.values():
        archive_lock[entry.destination[1:]] = (entry.kind, entry.mode, entry.sha256, None, entry.link_target)
    inspect_member_archive(archive_path, archive_lock, "")
    if set(manifest) != {entry.destination for entry in locked.values()}:
        fail("runtime artifact manifest differs from lock")
    result = []
    for locked_entry in locked.values():
        expected = manifest[locked_entry.destination]
        content = f"sha256:{locked_entry.sha256}" if locked_entry.kind == "file" else "target64:" + base64.b64encode(locked_entry.link_target.encode()).decode()
        if (expected.kind, expected.mode, expected.uid, expected.gid, expected.content, expected.xattrs, expected.hardlink) != (locked_entry.kind, locked_entry.mode, "0", "0", content, "-", "-"):
            fail(f"runtime artifact manifest differs from lock: {locked_entry.destination}")
        result.append(Entry(locked_entry.destination, locked_entry.kind, locked_entry.mode, locked_entry.sha256, locked_entry.link_target, Path(archive_path), locked_entry.destination[1:]))
    return result


def config_entries(inputs, lock_path):
    lines = checked_bytes(lock_path).decode().splitlines()
    locked = {}
    for line in lines:
        fields = line.split("  ")
        if len(fields) != 2 or not SHA256.fullmatch(fields[0]) or fields[1] in locked:
            fail("invalid fixed rootfs policy lock")
        locked[canonical(fields[1])] = fields[0]
    if tuple(path for path, _ in inputs) != CONFIG_PATHS or set(locked) != set(CONFIG_PATHS):
        fail("fixed rootfs configuration differs from policy lock")
    result = []
    for relative, source in inputs:
        source = Path(source)
        content = checked_bytes(source)
        digest = hashlib.sha256(content).hexdigest()
        if digest != locked[relative]:
            fail(f"fixed configuration hash differs: {relative}")
        result.append(Entry("/" + relative, "file", "0644", digest, replacement=content))
    return result


@contextlib.contextmanager
def content(entry):
    if entry.replacement is not None:
        yield io.BytesIO(entry.replacement)
    elif entry.source is not None:
        with entry.source.open("rb") as stream:
            yield stream
    else:
        with checked_descriptor(entry.archive) as (descriptor, _):
            with os.fdopen(os.dup(descriptor), "rb") as raw, tarfile.open(fileobj=raw, mode="r:") as archive:
                stream = archive.extractfile(archive.getmember(entry.member))
                yield stream


class HashReader:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def read(self, size=-1):
        data = self.stream.read(size)
        self.digest.update(data)
        return data


def finalize(entries):
    for path, target in LINKS.items():
        add(entries, Entry(path, "symlink", "0777", link=target))
    directories = {"/", *SKELETON}
    for path in entries:
        directories.update(str(parent) for parent in PurePosixPath(path).parents if str(parent) != "/")
    for path in sorted(directories, key=lambda value: value.encode()):
        if path in entries:
            if entries[path].kind != "dir":
                fail(f"directory collides with non-directory: {path}")
        else:
            add(entries, Entry(path, "dir", "0755"))
    symlinks = {path for path, entry in entries.items() if entry.kind == "symlink"}
    for path in entries:
        if any(str(parent) in symlinks for parent in PurePosixPath(path).parents):
            fail(f"symlink ancestor in final rootfs: {path}")
    non_directories = sum(entry.kind != "dir" for entry in entries.values())
    if non_directories != 167 or len(directories) != 34 or len(entries) != 201:
        fail(f"final rootfs inventory differs from fixed 167/34/201 contract: {non_directories}/{len(directories)}/{len(entries)}")
    modules = {path for path in entries if path.endswith((".ko", ".ko.gz", ".ko.xz", ".ko.zst"))}
    if modules != rootfs_manifest.REQUIRED_MODULES or any(path == "/usr/lib/modules" or path.startswith("/usr/lib/modules/") for path in entries):
        fail("final rootfs module inventory differs from fixed contract")
    if set(entries) & FORBIDDEN_EXACT:
        fail("final rootfs contains a fixed forbidden path")
    forbidden_parts = {"systemd", "sysctl.d", "tmpfiles.d", "templates"}
    if any(forbidden_parts & set(PurePosixPath(path).parts) for path in entries):
        fail("final rootfs contains forbidden policy or template content")
    if any("tdx" in PurePosixPath(path).name.lower() and path.endswith((".ko", ".ko.xz", ".ko.zst")) for path in entries):
        fail("final rootfs contains a TDX module")
    return entries


def manifest_entry(entry):
    if entry.kind == "file":
        value = "sha256:" + entry.digest
    elif entry.kind == "symlink":
        value = "target64:" + base64.b64encode(entry.link.encode()).decode()
    else:
        value = "-"
    return rootfs_manifest.Entry(entry.path, entry.kind, entry.mode, "0", "0", value, "-", "-")


def write_outputs(entries, output_tar, output_manifest):
    ordered = [entries[path] for path in sorted(entries, key=lambda value: value.encode())]
    manifest_entries = [manifest_entry(entry) for entry in ordered]
    violations = rootfs_manifest.policy_violations({entry.path: entry for entry in manifest_entries})
    if violations:
        fail("rootfs policy rejected assembly: " + "; ".join(f"{path}: {reason}" for path, reason in violations))
    temporary_tar = Path(str(output_tar) + ".tmp")
    temporary_manifest = Path(str(output_manifest) + ".tmp")
    for path in (Path(output_tar), Path(output_manifest), temporary_tar, temporary_manifest):
        if path.exists() or path.is_symlink():
            fail(f"output already exists: {path}")
    try:
        with temporary_tar.open("xb") as raw, tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for entry in ordered:
                member = tarfile.TarInfo("." if entry.path == "/" else entry.path[1:])
                member.mode, member.uid, member.gid, member.uname, member.gname, member.mtime = int(entry.mode, 8), 0, 0, "", "", 0
                if entry.kind == "dir":
                    member.type, member.size = tarfile.DIRTYPE, 0
                    archive.addfile(member)
                elif entry.kind == "symlink":
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, entry.link, 0
                    archive.addfile(member)
                else:
                    member.type = tarfile.REGTYPE
                    if entry.replacement is not None:
                        member.size = len(entry.replacement)
                    elif entry.source is not None:
                        member.size = entry.source.stat().st_size
                    else:
                        with checked_descriptor(entry.archive) as (descriptor, _):
                            with os.fdopen(os.dup(descriptor), "rb") as raw, tarfile.open(fileobj=raw, mode="r:") as source_archive:
                                member.size = source_archive.getmember(entry.member).size
                    with content(entry) as stream:
                        checked = HashReader(stream)
                        archive.addfile(member, checked)
                        if checked.digest.hexdigest() != entry.digest:
                            fail(f"source changed while assembling: {entry.path}")
        temporary_manifest.write_bytes(rootfs_manifest.serialize(manifest_entries))
        verify_output(temporary_tar, manifest_entries)
        os.replace(temporary_tar, output_tar)
        os.replace(temporary_manifest, output_manifest)
    except Exception:
        for path in (temporary_tar, temporary_manifest, Path(output_tar), Path(output_manifest)):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        raise


def verify_output(path, expected):
    actual = []
    with tarfile.open(path, "r:") as archive:
        for member in archive.getmembers():
            if member.pax_headers or member.uid or member.gid or member.uname or member.gname or member.mtime:
                fail(f"non-canonical final archive metadata: {member.name}")
            destination = "/" if member.name == "." else "/" + canonical(member.name)
            if member.isdir():
                actual.append(rootfs_manifest.Entry(destination, "dir", f"{member.mode:04o}", "0", "0", "-", "-", "-"))
            elif member.issym():
                safe_link(destination, member.linkname)
                value = "target64:" + base64.b64encode(member.linkname.encode()).decode()
                actual.append(rootfs_manifest.Entry(destination, "symlink", f"{member.mode:04o}", "0", "0", value, "-", "-"))
            elif member.isfile():
                digest = hashlib.file_digest(archive.extractfile(member), "sha256").hexdigest()
                actual.append(rootfs_manifest.Entry(destination, "file", f"{member.mode:04o}", "0", "0", "sha256:" + digest, "-", "-"))
            else:
                fail(f"forbidden final archive member type: {member.name}")
    if actual != expected:
        fail("final archive and manifest differ")


def assemble(args):
    entries = {}
    for entry in archive_entries(args.package, load_json(args.package_lock), True):
        add(entries, entry)
    for entry in archive_entries(args.vendor, load_json(args.vendor_lock), False):
        add(entries, entry)
    for entry in runtime_entries(args.runtime_archive, args.runtime_manifest, args.runtime_lock):
        add(entries, entry)
    for entry in config_entries(args.config, args.config_lock):
        add(entries, entry)
    write_outputs(finalize(entries), args.output_tar, args.output_manifest)


def parser():
    result = argparse.ArgumentParser()
    result.add_argument("--package-lock", required=True)
    result.add_argument("--vendor-lock", required=True)
    result.add_argument("--runtime-lock", required=True)
    result.add_argument("--runtime-archive", required=True)
    result.add_argument("--runtime-manifest", required=True)
    result.add_argument("--config-lock", required=True)
    result.add_argument("--package", action="append", nargs=2, default=[])
    result.add_argument("--vendor", action="append", nargs=2, default=[])
    result.add_argument("--config", action="append", nargs=2, default=[])
    result.add_argument("--output-tar", required=True)
    result.add_argument("--output-manifest", required=True)
    return result


def main():
    try:
        assemble(parser().parse_args())
    except (AssemblyError, rootfs_manifest.ManifestError, ValueError, OSError) as error:
        raise SystemExit(f"rootfs assembly: {error}") from error


if __name__ == "__main__":
    main()
