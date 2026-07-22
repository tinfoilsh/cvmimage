#!/usr/bin/env python3

import argparse
import base64
import binascii
import errno
import hashlib
import json
import os
import posixpath
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


FIELD_NAMES = ("type", "mode", "uid", "gid", "content", "xattrs", "hardlink")
ENTRY_TYPES = {"file", "dir", "symlink", "char", "block", "fifo", "socket"}
ABSENT = "<absent>"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"[0-7]{4}\Z")
DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
DEVICE_RE = re.compile(r"dev:(0|[1-9][0-9]*):(0|[1-9][0-9]*)\Z")
MODULE_DIRECTORY = "/usr/lib/tinfoil/kernel-modules"
REQUIRED_MODULES = {
    f"{MODULE_DIRECTORY}/nvidia-modeset.ko",
    f"{MODULE_DIRECTORY}/nvidia-uvm.ko",
    f"{MODULE_DIRECTORY}/nvidia.ko",
}
FORBIDDEN_TREES = (
    "/EFI",
    "/boot",
    "/efi",
    "/etc/apt",
    "/etc/dpkg",
    "/etc/ld.so.conf.d",
    "/etc/systemd",
    "/etc/sysctl.d",
    "/etc/tinfoil/templates",
    "/etc/tmpfiles.d",
    "/home",
    "/lib/systemd",
    "/root",
    "/snap",
    "/usr/lib/apt",
    "/usr/lib/debconf",
    "/usr/lib/dpkg",
    "/usr/lib/modules",
    "/usr/lib/snapd",
    "/usr/lib/systemd",
    "/usr/lib/sysctl.d",
    "/usr/lib/tmpfiles.d",
    "/usr/share/tinfoil/templates",
    "/var/cache/apt",
    "/var/cache/debconf",
    "/var/lib/apt",
    "/var/lib/debconf",
    "/var/lib/dpkg",
    "/var/lib/snapd",
    "/var/log",
)
REQUIRED_EMPTY_MOUNTPOINTS = ("/dev", "/proc", "/run", "/sys")
OPTIONAL_EMPTY_RUNTIME_DIRECTORIES = (
    "/mnt/ramdisk",
    "/var/lib/containerd",
    "/var/lib/docker",
)
FORBIDDEN_PATHS = {
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/shells",
    "/etc/sysctl.conf",
    "/sbin/ldconfig",
    "/sbin/sysctl",
    "/usr/bin/apt",
    "/usr/bin/apt-cache",
    "/usr/bin/apt-cdrom",
    "/usr/bin/apt-config",
    "/usr/bin/apt-get",
    "/usr/bin/apt-mark",
    "/usr/bin/debconf",
    "/usr/bin/debconf-apt-progress",
    "/usr/bin/debconf-communicate",
    "/usr/bin/debconf-copydb",
    "/usr/bin/debconf-escape",
    "/usr/bin/debconf-set-selections",
    "/usr/bin/debconf-show",
    "/usr/bin/dpkg",
    "/usr/bin/dpkg-deb",
    "/usr/bin/dpkg-divert",
    "/usr/bin/dpkg-maintscript-helper",
    "/usr/bin/dpkg-query",
    "/usr/bin/dpkg-realpath",
    "/usr/bin/dpkg-split",
    "/usr/bin/dpkg-statoverride",
    "/usr/bin/dpkg-trigger",
    "/usr/bin/docker-init",
    "/usr/bin/nvidia-smi",
    "/usr/lib/docker/docker-init",
    "/usr/libexec/docker/docker-init",
    "/usr/sbin/ldconfig",
    "/usr/sbin/sysctl",
    "/usr/sbin/update-alternatives",
}
MODULE_SUFFIXES = (".ko", ".ko.gz", ".ko.xz", ".ko.zst")
SHELL_NAMES = ("ash", "bash", "busybox", "csh", "dash", "fish", "ksh", "rbash", "sh", "tcsh", "zsh")
SYSTEMD_TOOLS = (
    "busctl",
    "coredumpctl",
    "hostnamectl",
    "journalctl",
    "localectl",
    "loginctl",
    "machinectl",
    "networkctl",
    "resolvectl",
    "systemctl",
    "systemd",
    "systemd-analyze",
    "systemd-ask-password",
    "systemd-cat",
    "systemd-creds",
    "systemd-detect-virt",
    "systemd-escape",
    "systemd-firstboot",
    "systemd-id128",
    "systemd-machine-id-setup",
    "systemd-mount",
    "systemd-notify",
    "systemd-path",
    "systemd-repart",
    "systemd-run",
    "systemd-socket-activate",
    "systemd-sysusers",
    "systemd-tmpfiles",
    "systemd-tty-ask-password-agent",
    "systemd-umount",
    "timedatectl",
)
FORBIDDEN_PATHS.update(f"{directory}/{name}" for directory in ("/bin", "/usr/bin") for name in SHELL_NAMES)
FORBIDDEN_PATHS.update(f"/usr/bin/{name}" for name in SYSTEMD_TOOLS)


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    mode: str
    uid: str
    gid: str
    content: str
    xattrs: str
    hardlink: str

    def fields(self) -> tuple[str, ...]:
        return (
            self.path,
            self.kind,
            self.mode,
            self.uid,
            self.gid,
            self.content,
            self.xattrs,
            self.hardlink,
        )

    def field(self, name: str) -> str:
        if name == "type":
            return self.kind
        return getattr(self, name)


@dataclass(frozen=True)
class RawEntry:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    content: str
    xattrs: str
    device: int
    inode: int
    links: int


def fail(message: str) -> None:
    raise ManifestError(message)


def path_bytes(path: str) -> bytes:
    try:
        return path.encode("utf-8")
    except UnicodeEncodeError as error:
        fail(f"path is not valid UTF-8: {path!r}: {error}")


def decode_name(name: str, parent: str) -> tuple[str, bytes]:
    raw = os.fsencode(name)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{parent}: filename is not valid UTF-8: {raw!r}: {error}")
    if "\t" in decoded or "\n" in decoded or "\r" in decoded:
        fail(f"{parent}: filename contains a forbidden control character: {decoded!r}")
    return decoded, raw


def canonical_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def validate_base64(value: str, context: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        fail(f"{context}: invalid base64: {error}")
    if canonical_base64(decoded) != value:
        fail(f"{context}: non-canonical base64")
    return decoded


def validate_path(path: str, context: str) -> None:
    if not path.startswith("/"):
        fail(f"{context}: path must be absolute: {path}")
    if "\t" in path or "\n" in path or "\r" in path or "\0" in path:
        fail(f"{context}: path contains a forbidden control character: {path!r}")
    if path != "/" and path.endswith("/"):
        fail(f"{context}: path has a trailing slash: {path}")
    if posixpath.normpath(path) != path or path.startswith("//"):
        fail(f"{context}: path is not normalized: {path}")
    path_bytes(path)


def canonical_xattrs_for_fd(file_descriptor: int, context: str) -> str:
    try:
        names = os.listxattr(file_descriptor)
    except OSError as error:
        fail(f"{context}: cannot list xattrs: {error}")
    attributes = {}
    for name in names:
        raw_name = os.fsencode(name)
        try:
            decoded_name = raw_name.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"{context}: xattr name is not valid UTF-8: {raw_name!r}: {error}")
        try:
            value = os.getxattr(file_descriptor, name)
        except OSError as error:
            fail(f"{context}: cannot read xattr {decoded_name!r}: {error}")
        attributes[decoded_name] = canonical_base64(value)
    return canonical_xattrs(attributes)


def canonical_xattrs_for_path(path: str, context: str) -> str:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        fail(f"{context}: cannot list xattrs: {error}")
    attributes = {}
    for name in names:
        raw_name = os.fsencode(name)
        try:
            decoded_name = raw_name.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"{context}: xattr name is not valid UTF-8: {raw_name!r}: {error}")
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            fail(f"{context}: cannot read xattr {decoded_name!r}: {error}")
        attributes[decoded_name] = canonical_base64(value)
    return canonical_xattrs(attributes)


def canonical_xattrs(attributes: dict[str, str]) -> str:
    if not attributes:
        return "-"
    return json.dumps(attributes, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def validate_xattrs(value: str, context: str) -> None:
    if value == "-":
        return
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        fail(f"{context}: invalid xattr JSON: {error}")
    if not isinstance(parsed, dict) or not parsed:
        fail(f"{context}: xattrs must be '-' or a non-empty JSON object")
    for name, encoded in parsed.items():
        if not isinstance(name, str) or not name:
            fail(f"{context}: xattr names must be non-empty strings")
        if "\t" in name or "\n" in name or "\r" in name:
            fail(f"{context}: xattr name contains a forbidden control character")
        if not isinstance(encoded, str):
            fail(f"{context}: xattr values must be base64 strings")
        validate_base64(encoded, f"{context}: xattr {name!r}")
    if canonical_xattrs(parsed) != value:
        fail(f"{context}: xattr JSON is not canonical")


def hash_fd(file_descriptor: int, context: str) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(file_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as error:
        fail(f"{context}: cannot hash file: {error}")
    return digest.hexdigest()


def same_object(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
    )


def stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_rdev,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def require_stable_metadata(
    before: os.stat_result, after: os.stat_result, context: str
) -> None:
    if not same_object(before, after) or stable_metadata(before) != stable_metadata(after):
        fail(f"{context}: entry changed while being inventoried")


def open_verified_directory(path: Path, context: str) -> int:
    raw_path = os.fspath(path)
    if not raw_path:
        fail(f"{context}: empty path")
    absolute = os.path.isabs(raw_path)
    components = raw_path.split(os.sep)
    if any(component == os.pardir for component in components):
        fail(f"{context}: parent traversal is not allowed: {raw_path}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        current_fd = os.open(os.sep if absolute else os.curdir, flags)
    except OSError as error:
        fail(f"{context}: cannot open traversal root: {error}")
    try:
        for component in components:
            if component in {"", os.curdir}:
                continue
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as error:
                fail(f"{context}: cannot safely open directory component {component!r}: {error}")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def classify(metadata: os.stat_result, context: str) -> str:
    mode = metadata.st_mode
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISCHR(mode):
        return "char"
    if stat.S_ISBLK(mode):
        return "block"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    fail(f"{context}: unsupported filesystem object mode {mode:#o}")


class Inventory:
    def __init__(self, root: Path):
        self.root = root
        self.entries: list[RawEntry] = []

    def collect(self) -> list[Entry]:
        root_fd = open_verified_directory(self.root, f"cannot open root directory {self.root}")
        try:
            root_metadata = os.fstat(root_fd)
            root_xattrs = canonical_xattrs_for_fd(root_fd, "/")
            self.entries.append(
                RawEntry(
                    "/",
                    "dir",
                    stat.S_IMODE(root_metadata.st_mode),
                    root_metadata.st_uid,
                    root_metadata.st_gid,
                    "-",
                    root_xattrs,
                    root_metadata.st_dev,
                    root_metadata.st_ino,
                    root_metadata.st_nlink,
                )
            )
            self._walk(root_fd, "/")
            final_root_metadata = os.fstat(root_fd)
            require_stable_metadata(root_metadata, final_root_metadata, "/")
            if canonical_xattrs_for_fd(root_fd, "/") != root_xattrs:
                fail("/: xattrs changed while being inventoried")
        finally:
            os.close(root_fd)
        return self._finalize()

    def _walk(self, directory_fd: int, parent_path: str) -> None:
        names = self._directory_names(directory_fd, parent_path)
        for name, raw_name in names:
            self._collect_name(directory_fd, parent_path, name, raw_name)
        if self._directory_names(directory_fd, parent_path) != names:
            fail(f"{parent_path}: directory entries changed while being inventoried")

    def _directory_names(self, directory_fd: int, parent_path: str) -> list[tuple[str, bytes]]:
        try:
            raw_names = os.listdir(directory_fd)
        except OSError as error:
            fail(f"{parent_path}: cannot list directory: {error}")
        return sorted((decode_name(name, parent_path) for name in raw_names), key=lambda item: item[1])

    def _collect_name(
        self, directory_fd: int, parent_path: str, name: str, raw_name: bytes
    ) -> None:
        del raw_name
        path = f"/{name}" if parent_path == "/" else f"{parent_path}/{name}"
        validate_path(path, path)
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"{path}: cannot stat entry: {error}")
        kind = classify(metadata, path)
        if kind == "dir":
            self._collect_directory(directory_fd, name, path, metadata)
        elif kind == "file":
            self._collect_file(directory_fd, name, path, metadata)
        else:
            self._collect_special(directory_fd, name, path, metadata, kind)

    def _collect_directory(
        self, directory_fd: int, name: str, path: str, metadata: os.stat_result
    ) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            child_fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError as error:
            fail(f"{path}: cannot safely open directory: {error}")
        try:
            opened_metadata = os.fstat(child_fd)
            require_stable_metadata(metadata, opened_metadata, path)
            xattrs = canonical_xattrs_for_fd(child_fd, path)
            self.entries.append(
                RawEntry(
                    path,
                    "dir",
                    stat.S_IMODE(opened_metadata.st_mode),
                    opened_metadata.st_uid,
                    opened_metadata.st_gid,
                    "-",
                    xattrs,
                    opened_metadata.st_dev,
                    opened_metadata.st_ino,
                    opened_metadata.st_nlink,
                )
            )
            self._walk(child_fd, path)
            final_metadata = os.fstat(child_fd)
            require_stable_metadata(opened_metadata, final_metadata, path)
            if canonical_xattrs_for_fd(child_fd, path) != xattrs:
                fail(f"{path}: xattrs changed while being inventoried")
        finally:
            os.close(child_fd)

    def _collect_file(
        self, directory_fd: int, name: str, path: str, metadata: os.stat_result
    ) -> None:
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            file_fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError as error:
            fail(f"{path}: cannot safely open file: {error}")
        try:
            opened_metadata = os.fstat(file_fd)
            if not stat.S_ISREG(opened_metadata.st_mode):
                fail(f"{path}: opened entry is not a regular file")
            require_stable_metadata(metadata, opened_metadata, path)
            digest = hash_fd(file_fd, path)
            xattrs = canonical_xattrs_for_fd(file_fd, path)
            final_metadata = os.fstat(file_fd)
            require_stable_metadata(opened_metadata, final_metadata, path)
            if canonical_xattrs_for_fd(file_fd, path) != xattrs:
                fail(f"{path}: xattrs changed while being inventoried")
            self.entries.append(
                RawEntry(
                    path,
                    "file",
                    stat.S_IMODE(final_metadata.st_mode),
                    final_metadata.st_uid,
                    final_metadata.st_gid,
                    f"sha256:{digest}",
                    xattrs,
                    final_metadata.st_dev,
                    final_metadata.st_ino,
                    final_metadata.st_nlink,
                )
            )
        finally:
            os.close(file_fd)

    def _collect_special(
        self,
        directory_fd: int,
        name: str,
        path: str,
        metadata: os.stat_result,
        kind: str,
    ) -> None:
        proc_path = f"/proc/self/fd/{directory_fd}/{name}"
        if kind == "symlink":
            try:
                target = os.readlink(name, dir_fd=directory_fd)
            except OSError as error:
                fail(f"{path}: cannot read symlink: {error}")
            content = f"target64:{canonical_base64(os.fsencode(target))}"
        elif kind in {"char", "block"}:
            content = f"dev:{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}"
        else:
            content = "-"
        xattrs = canonical_xattrs_for_path(proc_path, path)
        try:
            final_metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"{path}: entry disappeared while being inventoried: {error}")
        require_stable_metadata(metadata, final_metadata, path)
        if kind == "symlink":
            try:
                final_target = os.readlink(name, dir_fd=directory_fd)
            except OSError as error:
                fail(f"{path}: cannot re-read symlink: {error}")
            if os.fsencode(final_target) != os.fsencode(target):
                fail(f"{path}: symlink target changed while being inventoried")
        if canonical_xattrs_for_path(proc_path, path) != xattrs:
            fail(f"{path}: xattrs changed while being inventoried")
        self.entries.append(
            RawEntry(
                path,
                kind,
                stat.S_IMODE(final_metadata.st_mode),
                final_metadata.st_uid,
                final_metadata.st_gid,
                content,
                xattrs,
                final_metadata.st_dev,
                final_metadata.st_ino,
                final_metadata.st_nlink,
            )
        )

    def _finalize(self) -> list[Entry]:
        hardlink_paths: dict[tuple[int, int], list[str]] = {}
        for entry in self.entries:
            if entry.kind == "file" and entry.links > 1:
                hardlink_paths.setdefault((entry.device, entry.inode), []).append(entry.path)
        hardlink_roots = {
            identity: min(paths, key=path_bytes) for identity, paths in hardlink_paths.items()
        }
        for identity in hardlink_paths:
            members = [
                entry
                for entry in self.entries
                if entry.kind == "file" and (entry.device, entry.inode) == identity
            ]
            shared = {
                (entry.mode, entry.uid, entry.gid, entry.content, entry.xattrs, entry.links)
                for entry in members
            }
            if len(shared) != 1:
                fail(f"hardlink group {hardlink_roots[identity]} changed while being inventoried")
        result = []
        for entry in sorted(self.entries, key=lambda item: path_bytes(item.path)):
            hardlink = "-"
            identity = (entry.device, entry.inode)
            if entry.kind == "file" and entry.links > 1:
                hardlink = f"path64:{canonical_base64(path_bytes(hardlink_roots[identity]))}"
            result.append(
                Entry(
                    entry.path,
                    entry.kind,
                    f"{entry.mode:04o}",
                    str(entry.uid),
                    str(entry.gid),
                    entry.content,
                    entry.xattrs,
                    hardlink,
                )
            )
        return result


def serialize(entries: list[Entry]) -> bytes:
    return ("\n".join("\t".join(entry.fields()) for entry in entries) + "\n").encode("utf-8")


def write_output(path: str, data: bytes) -> None:
    if path == "-":
        sys.stdout.buffer.write(data)
        return
    destination = Path(path)
    destination_name = destination.name
    if destination_name in {"", os.curdir, os.pardir}:
        fail(f"cannot write manifest {destination}: invalid destination name")
    parent_fd = open_verified_directory(destination.parent, f"manifest parent {destination.parent}")
    temporary_name = ""
    temporary_fd = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        for _ in range(128):
            temporary_name = f".{destination_name}.tmp.{secrets.token_hex(16)}"
            try:
                temporary_fd = os.open(temporary_name, flags, 0o666, dir_fd=parent_fd)
                break
            except FileExistsError:
                continue
        else:
            fail(f"cannot create an exclusive temporary manifest in {destination.parent}")
        view = memoryview(data)
        while view:
            written = os.write(temporary_fd, view)
            if written == 0:
                fail(f"cannot write manifest {destination}: short write")
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_name = ""
        os.fsync(parent_fd)
    except OSError as error:
        fail(f"cannot write manifest {destination}: {error}")
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def parse_manifest(path: Path) -> dict[str, Entry]:
    try:
        data = path.read_bytes()
    except OSError as error:
        fail(f"cannot read manifest {path}: {error}")
    return parse_content(path, data)


def parse_content(path: Path, data: bytes) -> dict[str, Entry]:
    if not data:
        fail(f"{path}: manifest is empty")
    if not data.endswith(b"\n"):
        fail(f"{path}: manifest must end with a newline")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{path}: manifest is not valid UTF-8: {error}")
    entries: dict[str, Entry] = {}
    previous_path: str | None = None
    for number, line in enumerate(text[:-1].split("\n"), 1):
        if not line:
            fail(f"{path}:{number}: blank lines are not allowed")
        if line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 8:
            fail(f"{path}:{number}: expected exactly eight tab-separated fields")
        entry = Entry(*fields)
        context = f"{path}:{number}"
        validate_entry(entry, context)
        if entry.path in entries:
            fail(f"{context}: duplicate path: {entry.path}")
        if previous_path is not None and path_bytes(entry.path) <= path_bytes(previous_path):
            fail(f"{context}: records are not in strict bytewise path order")
        entries[entry.path] = entry
        previous_path = entry.path
    if not entries:
        fail(f"{path}: manifest has no records")
    validate_hardlinks(entries, str(path))
    return entries


def validate_entry(entry: Entry, context: str) -> None:
    validate_path(entry.path, context)
    if entry.kind not in ENTRY_TYPES:
        fail(f"{context}: unsupported type: {entry.kind}")
    if not MODE_RE.fullmatch(entry.mode):
        fail(f"{context}: mode must be exactly four octal digits")
    if not DECIMAL_RE.fullmatch(entry.uid) or not DECIMAL_RE.fullmatch(entry.gid):
        fail(f"{context}: uid and gid must be canonical non-negative decimals")
    validate_xattrs(entry.xattrs, context)
    if entry.kind == "file":
        if not SHA256_RE.fullmatch(entry.content):
            fail(f"{context}: regular file content must be a lowercase SHA-256")
    elif entry.kind == "symlink":
        if not entry.content.startswith("target64:"):
            fail(f"{context}: symlink content must use target64")
        validate_base64(entry.content.removeprefix("target64:"), f"{context}: symlink target")
    elif entry.kind in {"char", "block"}:
        if not DEVICE_RE.fullmatch(entry.content):
            fail(f"{context}: device content must use canonical dev:<major>:<minor>")
    elif entry.content != "-":
        fail(f"{context}: {entry.kind} content must be '-'")
    if entry.hardlink != "-":
        if entry.kind != "file" or not entry.hardlink.startswith("path64:"):
            fail(f"{context}: only regular files may have path64 hardlink groups")
        decoded = validate_base64(
            entry.hardlink.removeprefix("path64:"), f"{context}: hardlink path"
        )
        try:
            target = decoded.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"{context}: hardlink path is not valid UTF-8: {error}")
        validate_path(target, f"{context}: hardlink path")


def validate_hardlinks(entries: dict[str, Entry], context: str) -> None:
    groups: dict[str, list[str]] = {}
    for entry in entries.values():
        if entry.hardlink != "-":
            groups.setdefault(entry.hardlink, []).append(entry.path)
    for encoded, paths in groups.items():
        target = base64.b64decode(encoded.removeprefix("path64:")).decode("utf-8")
        if target not in entries or entries[target].kind != "file":
            fail(f"{context}: hardlink group target is not a regular manifest path: {target}")
        first = min(paths, key=path_bytes)
        if target != first:
            fail(f"{context}: hardlink group target {target} is not its first bytewise path {first}")
        shared_fields = ("type", "mode", "uid", "gid", "content", "xattrs")
        for path in paths:
            for field in shared_fields:
                if entries[path].field(field) != entries[target].field(field):
                    fail(f"{context}: hardlink group {target} has differing {field}")


def compare_manifests(
    expected: dict[str, Entry],
    actual: dict[str, Entry],
) -> list[str]:
    failures = []

    def report(path: str, field: str, expected_value: str, actual_value: str) -> None:
        failures.append("difference\t" + "\t".join((path, field, expected_value, actual_value)))

    for path in sorted(set(expected) | set(actual), key=path_bytes):
        if path not in actual:
            report(path, "path", path, ABSENT)
            continue
        if path not in expected:
            report(path, "path", ABSENT, path)
            continue
        for field in FIELD_NAMES:
            expected_value = expected[path].field(field)
            actual_value = actual[path].field(field)
            if expected_value != actual_value:
                report(path, field, expected_value, actual_value)
    return failures


def path_in_tree(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def capability_xattrs(entry: Entry) -> list[str]:
    if entry.xattrs == "-":
        return []
    attributes = json.loads(entry.xattrs)
    return sorted(name for name in attributes if "capability" in name.lower())


def policy_violations(entries: dict[str, Entry]) -> list[tuple[str, str]]:
    violations: list[tuple[str, str]] = []
    for path, entry in entries.items():
        mode = int(entry.mode, 8)
        if entry.kind != "symlink" and mode & 0o002:
            violations.append((path, "world-writable non-symlink object"))
        if mode & 0o7000:
            violations.append((path, "setuid, setgid, and sticky bits are forbidden"))
        for name in capability_xattrs(entry):
            violations.append((path, f"capability xattr is forbidden: {name}"))
        if entry.kind in {"char", "block", "fifo", "socket"}:
            violations.append((path, f"special object is forbidden: {entry.kind}"))
        if path in FORBIDDEN_PATHS or any(
            path_in_tree(path, root) for root in FORBIDDEN_TREES
        ):
            violations.append((path, "forbidden immutable rootfs path"))
        if path.endswith(MODULE_SUFFIXES) and path not in REQUIRED_MODULES:
            violations.append((path, "kernel module is outside the fixed NVIDIA module set"))
        if (
            path_in_tree(path, MODULE_DIRECTORY)
            and path not in REQUIRED_MODULES
            and path != MODULE_DIRECTORY
        ):
            violations.append((path, "extra entry in the fixed NVIDIA module directory"))
        runtime_directories = (
            REQUIRED_EMPTY_MOUNTPOINTS
            + OPTIONAL_EMPTY_RUNTIME_DIRECTORIES
            + ("/tmp", "/var/tmp")
        )
        for directory in runtime_directories:
            if path == directory and entry.kind != "dir":
                violations.append((path, "runtime mountpoint must be a directory"))
            elif path.startswith(directory + "/"):
                violations.append((path, "runtime state must be created by PID1"))

    for path in REQUIRED_EMPTY_MOUNTPOINTS + ("/tmp", "/var/tmp"):
        entry = entries.get(path)
        if entry is None:
            violations.append((path, "required root-owned 0755 mountpoint is missing"))
        elif (entry.kind, entry.mode, entry.uid, entry.gid) != ("dir", "0755", "0", "0"):
            violations.append((path, "mountpoint must be a root-owned 0755 directory"))

    for path in sorted(REQUIRED_MODULES, key=path_bytes):
        entry = entries.get(path)
        if entry is None:
            violations.append((path, "required NVIDIA module is missing"))
        elif (entry.kind, entry.mode, entry.uid, entry.gid, entry.xattrs, entry.hardlink) != (
            "file",
            "0644",
            "0",
            "0",
            "-",
            "-",
        ):
            violations.append(
                (path, "NVIDIA module must be an unlinked xattr-free root-owned 0644 regular file")
            )
    return sorted(violations, key=lambda item: (path_bytes(item[0]), item[1]))


def command_inventory(arguments: argparse.Namespace) -> int:
    entries = Inventory(Path(arguments.root)).collect()
    write_output(arguments.output, serialize(entries))
    return 0


def command_validate(arguments: argparse.Namespace) -> int:
    parse_manifest(Path(arguments.manifest))
    return 0


def command_compare(arguments: argparse.Namespace) -> int:
    expected = parse_manifest(Path(arguments.expected))
    actual = parse_manifest(Path(arguments.actual))
    failures = compare_manifests(expected, actual)
    for line in failures:
        print(line, file=sys.stderr)
    return 1 if failures else 0


def command_policy(arguments: argparse.Namespace) -> int:
    entries = parse_manifest(Path(arguments.manifest))
    violations = policy_violations(entries)
    for path, reason in violations:
        print(f"policy\t{path}\t{reason}", file=sys.stderr)
    return 1 if violations else 0


def parser() -> argparse.ArgumentParser:
    command_parser = argparse.ArgumentParser(
        description="Inventory and compare canonical additive-rootfs manifests."
    )
    subparsers = command_parser.add_subparsers(dest="command", required=True)

    inventory_parser = subparsers.add_parser("inventory", help="inventory an explicit root")
    inventory_parser.add_argument("--root", required=True, help="root directory to inventory")
    inventory_parser.add_argument("--output", required=True, help="manifest path or '-' for stdout")
    inventory_parser.set_defaults(function=command_inventory)

    validate_parser = subparsers.add_parser("validate", help="validate canonical manifest syntax")
    validate_parser.add_argument("manifest")
    validate_parser.set_defaults(function=command_validate)

    compare_parser = subparsers.add_parser("compare", help="compare manifests bidirectionally")
    compare_parser.add_argument("--expected", required=True)
    compare_parser.add_argument("--actual", required=True)
    compare_parser.set_defaults(function=command_compare)

    policy_parser = subparsers.add_parser("policy", help="enforce the fixed immutable rootfs policy")
    policy_parser.add_argument("manifest")
    policy_parser.set_defaults(function=command_policy)
    return command_parser


def main() -> int:
    os.environ["LC_ALL"] = "C"
    try:
        arguments = parser().parse_args()
        return arguments.function(arguments)
    except ManifestError as error:
        print(f"rootfs_manifest.py: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
