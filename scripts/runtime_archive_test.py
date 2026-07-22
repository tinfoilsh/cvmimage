import gzip
import hashlib
import io
import json
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.runtime_archive import (
    ArchiveError,
    _ar_members,
    _load_source_lock,
    _write_validation_marker,
    extract_locked_archive,
    validate_source_ids,
)


def _file(path, data=b"payload", mode=0o644, **metadata):
    return {"path": path, "type": "file", "data": data, "mode": mode, **metadata}


def _symlink(path, target, mode=0o777):
    return {"path": path, "type": "symlink", "target": target, "mode": mode}


def _tar_bytes(entries):
    output = io.BytesIO()
    archive_format = tarfile.PAX_FORMAT if any(entry.get("pax_headers") for entry in entries) else tarfile.GNU_FORMAT
    with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
        for entry in entries:
            member = tarfile.TarInfo(entry["path"])
            member.mode = entry.get("mode", 0o644)
            member.uid = entry.get("uid", 0)
            member.gid = entry.get("gid", 0)
            member.pax_headers = entry.get("pax_headers", {})
            if entry["type"] == "file":
                member.size = len(entry["data"])
                archive.addfile(member, io.BytesIO(entry["data"]))
            elif entry["type"] == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = entry["target"]
                archive.addfile(member)
            elif entry["type"] == "dir":
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif entry["type"] == "fifo":
                member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            elif entry["type"] == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = entry["target"]
                archive.addfile(member)
    return output.getvalue()


def _ar_member(name, data):
    header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def _ar_member_with_size(name, size_field, data=b""):
    header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}".encode("ascii")
    return header + size_field + b"`\n" + data


def _deb_bytes(entries):
    return (
        b"!<arch>\n"
        + _ar_member("debian-binary", b"2.0\n")
        + _ar_member("control.tar.gz", gzip.compress(_tar_bytes([]), mtime=0))
        + _ar_member("data.tar.gz", gzip.compress(_tar_bytes(entries), mtime=0))
    )


def _locked(entries, archive_sha256, kind="tar"):
    files = []
    for entry in entries:
        item = {"mode": f"{entry.get('mode', 0o644):04o}", "path": entry["path"], "type": entry["type"]}
        if entry["type"] == "file":
            item["sha256"] = hashlib.sha256(entry["data"]).hexdigest()
            item["size"] = len(entry["data"])
        else:
            item["target"] = entry["target"]
        files.append(item)
    if kind == "tar":
        return {
            "files": files,
            "id": "fixture",
            "kind": kind,
            "members": [entry["path"] for entry in entries],
            "sha256": archive_sha256,
            "url": "https://example.invalid/fixture.tar",
        }
    return {
        "architecture": "amd64",
        "control": {
            "architecture": "amd64",
            "depends": "",
            "package": "fixture",
            "pre_depends": "",
            "version": "1",
        },
        "files": files,
        "id": "fixture",
        "kind": kind,
        "package": "fixture",
        "paths": [entry["path"] for entry in entries],
        "sha256": archive_sha256,
        "url": "https://example.invalid/fixture.deb",
        "version": "1",
    }


def _package_locked(source_id, entries):
    files = []
    for entry in entries:
        item = {
            "gid": entry.get("gid", 0),
            "mode": f"{entry.get('mode', 0o644):04o}",
            "path": entry["path"],
            "type": entry["type"],
            "uid": entry.get("uid", 0),
            "xattrs": {},
        }
        if entry["type"] == "file":
            item["sha256"] = hashlib.sha256(entry["data"]).hexdigest()
            item["size"] = len(entry["data"])
        else:
            item["target"] = entry["target"]
        files.append(item)
    return {"version": 1, "sources": {source_id: {"files": files, "kind": "tar", "package_data": True}}}


class RuntimeArchiveTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def run_extract(self, archive_entries, locked_entries=None, kind="tar", deb=False):
        archive = self.root / ("fixture.deb" if deb else "fixture.tar")
        archive.write_bytes(_deb_bytes(archive_entries) if deb else _tar_bytes(archive_entries))
        lock = self.root / "source.json"
        selected = archive_entries if locked_entries is None else locked_entries
        archive_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
        lock.write_text(json.dumps(_locked(selected, archive_sha256, kind)), encoding="utf-8")
        output = self.root / "output.tar"
        extract_locked_archive(archive, lock, output)
        return output

    def assert_rejected(self, entries, locked_entries=None, kind="tar", deb=False):
        with self.assertRaises(ArchiveError):
            self.run_extract(entries, locked_entries, kind, deb)

    def assert_lock_rejected(self, source):
        lock = self.root / "source.json"
        lock.write_text(json.dumps(source), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            _load_source_lock(lock)

    def test_emits_only_locked_members_deterministically(self):
        selected = [_file("usr/bin/tool", b"tool", 0o755), _symlink("usr/bin/tool-link", "tool")]
        entries = [_file("usr/share/unselected", b"unused")] + selected
        first = self.run_extract(entries, selected).read_bytes()
        self.assertEqual(stat.S_IMODE((self.root / "output.tar").stat().st_mode), 0o644)
        second = self.run_extract(entries, selected).read_bytes()
        self.assertEqual(first, second)
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:") as archive:
            self.assertEqual([member.name for member in archive], ["usr/bin/tool", "usr/bin/tool-link"])
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))

    def test_extracts_synthetic_debian_data_archive(self):
        output = self.run_extract(
            [{"path": ".", "type": "dir"}, _file("./usr/bin/tool", b"tool", 0o755)],
            [_file("usr/bin/tool", b"tool", 0o755)],
            kind="deb",
            deb=True,
        )
        self.assertTrue(output.is_file())
        with tarfile.open(output, mode="r:") as archive:
            self.assertEqual(archive.getnames(), ["usr/bin/tool"])
            stream = archive.extractfile("usr/bin/tool")
            self.assertIsNotNone(stream)
            self.assertEqual(stream.read(), b"tool")

    def test_rejects_missing_member(self):
        self.assert_rejected([_file("usr/bin/other")], [_file("usr/bin/tool")])

    def test_rejects_absolute_path(self):
        self.assert_rejected([_file("/usr/bin/tool")])

    def test_rejects_traversal(self):
        self.assert_rejected([_file("usr/../bin/tool")])

    def test_rejects_path_aliases(self):
        self.assert_rejected([_file("usr/bin/tool"), _file("./usr/bin/tool")])

    def test_rejects_single_tar_dot_prefix_alias(self):
        self.assert_rejected([_file("./usr/bin/tool")], [_file("usr/bin/tool")])

    def test_rejects_archive_hash_mutation(self):
        archive = self.root / "fixture.tar"
        entries = [_file("usr/bin/tool")]
        archive.write_bytes(_tar_bytes(entries))
        lock = self.root / "source.json"
        lock.write_text(json.dumps(_locked(entries, "0" * 64)), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            extract_locked_archive(archive, lock, self.root / "output.tar")

    def test_unified_non_package_source_requires_archive_hash(self):
        lock = self.root / "source.json"
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        source.pop("sha256")
        source["package_data"] = False
        lock.write_text(json.dumps({"version": 1, "sources": {"fixture": source}}), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            _load_source_lock(lock, "fixture")

    def test_unified_non_package_source_accepts_exact_archive_hash(self):
        lock = self.root / "source.json"
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        for field in ("id", "members", "url"):
            source.pop(field)
        source["package_data"] = False
        lock.write_text(json.dumps({"version": 1, "sources": {"fixture": source}}), encoding="utf-8")
        kind, digest, _, package_data = _load_source_lock(lock, "fixture")
        self.assertEqual((kind, digest, package_data), ("tar", "0" * 64, False))

    def test_output_temp_symlink_is_not_followed(self):
        victim = self.root / "victim"
        victim.write_bytes(b"unchanged")
        collision = self.root / ".runtime-archive-collision"
        collision.symlink_to(victim)
        with mock.patch("scripts.runtime_archive.secrets.token_hex", side_effect=["collision", "fresh"]) as token_hex:
            output = self.run_extract([_file("usr/bin/tool")])
        self.assertEqual(token_hex.call_count, 2)
        self.assertTrue(output.is_file())
        self.assertTrue(collision.is_symlink())
        self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_rejects_symlink_output_parent(self):
        real = self.root / "real"
        real.mkdir()
        linked = self.root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        archive = self.root / "fixture.tar"
        entries = [_file("usr/bin/tool")]
        archive.write_bytes(_tar_bytes(entries))
        lock = self.root / "source.json"
        lock.write_text(json.dumps(_locked(entries, hashlib.sha256(archive.read_bytes()).hexdigest())), encoding="utf-8")
        with self.assertRaises(OSError):
            extract_locked_archive(archive, lock, linked / "output.tar")

    def test_rejects_output_parent_traversal(self):
        archive = self.root / "fixture.tar"
        entries = [_file("usr/bin/tool")]
        archive.write_bytes(_tar_bytes(entries))
        lock = self.root / "source.json"
        lock.write_text(json.dumps(_locked(entries, hashlib.sha256(archive.read_bytes()).hexdigest())), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            extract_locked_archive(archive, lock, self.root / "child" / ".." / "output.tar")

    def test_rejects_output_path_aliases(self):
        archive = self.root / "fixture.tar"
        entries = [_file("usr/bin/tool")]
        archive.write_bytes(_tar_bytes(entries))
        lock = self.root / "source.json"
        lock.write_text(json.dumps(_locked(entries, hashlib.sha256(archive.read_bytes()).hexdigest())), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            extract_locked_archive(archive, lock, str(self.root) + "//output.tar")

    def test_validation_marker_rejects_symlink_and_unsafe_parent(self):
        victim = self.root / "victim"
        victim.write_bytes(b"unchanged")
        marker = self.root / "marker"
        marker.symlink_to(victim)
        with self.assertRaises(ArchiveError):
            _write_validation_marker(marker)
        self.assertEqual(victim.read_bytes(), b"unchanged")
        real = self.root / "real"
        real.mkdir()
        linked = self.root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            _write_validation_marker(linked / "marker")

    def test_rejects_unexpected_type(self):
        entries = [_file("usr/bin/tool"), {"path": "usr/run/pipe", "type": "fifo"}]
        self.assert_rejected(entries, [_file("usr/bin/tool")])

    def test_rejects_hardlink(self):
        entries = [_file("usr/bin/tool"), {"path": "usr/bin/alias", "type": "hardlink", "target": "usr/bin/tool"}]
        self.assert_rejected(entries, [_file("usr/bin/tool")])

    def test_rejects_symlink_parent(self):
        self.assert_rejected([_symlink("usr/lib", "../outside"), _file("usr/lib/tool")], [_file("usr/lib/tool")])

    def test_rejects_escaping_symlink_target(self):
        self.assert_rejected([_symlink("usr/bin/tool", "../../../outside")])

    def test_rejects_type_mode_hash_and_link_mutations(self):
        self.assert_rejected([_symlink("usr/bin/tool", "target")], [_file("usr/bin/tool")])
        self.assert_rejected([_file("usr/bin/tool", mode=0o755)], [_file("usr/bin/tool", mode=0o644)])
        self.assert_rejected([_file("usr/bin/tool", b"changed")], [_file("usr/bin/tool", b"expected")])
        self.assert_rejected([_symlink("usr/bin/tool", "changed")], [_symlink("usr/bin/tool", "expected")])

    def test_package_data_authenticates_ownership_and_xattrs(self):
        source_id = "package_1_amd64"
        selected = [_file("usr/bin/tool")]
        lock = self.root / "source.json"
        lock.write_text(json.dumps(_package_locked(source_id, selected)), encoding="utf-8")
        archive = self.root / "fixture.tar"
        archive.write_bytes(_tar_bytes([_file("./usr/bin/tool", uid=1)]))
        with self.assertRaises(ArchiveError):
            extract_locked_archive(archive, lock, self.root / "output.tar", source_id)
        for pax_key in ("SCHILY.xattr.user.test", "LIBARCHIVE.xattr.user.test", "vendor.xattr.test"):
            archive.write_bytes(_tar_bytes([_file("./usr/bin/tool", pax_headers={pax_key: "value"})]))
            with self.assertRaises(ArchiveError):
                extract_locked_archive(archive, lock, self.root / "output.tar", source_id)

        output = io.BytesIO()
        with tarfile.open(
            fileobj=output,
            mode="w",
            format=tarfile.PAX_FORMAT,
            pax_headers={"LIBARCHIVE.xattr.user.test": "value"},
        ) as payload:
            member = tarfile.TarInfo("./usr/bin/tool")
            member.size = len(b"payload")
            payload.addfile(member, io.BytesIO(b"payload"))
        archive.write_bytes(output.getvalue())
        with self.assertRaises(ArchiveError):
            extract_locked_archive(archive, lock, self.root / "output.tar", source_id)

    def test_package_data_absolute_symlink_is_root_confined(self):
        source_id = "package_1_amd64"
        selected = [_symlink("usr/lib/ssl/openssl.cnf", "/etc/ssl/openssl.cnf")]
        lock = self.root / "source.json"
        lock.write_text(json.dumps(_package_locked(source_id, selected)), encoding="utf-8")
        archive = self.root / "fixture.tar"
        archive.write_bytes(_tar_bytes([_symlink("./usr/lib/ssl/openssl.cnf", "/etc/ssl/openssl.cnf")]))
        extract_locked_archive(archive, lock, self.root / "output.tar", source_id)
        escaped = [_symlink("usr/lib/ssl/openssl.cnf", "/../../outside")]
        lock.write_text(json.dumps(_package_locked(source_id, escaped)), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            extract_locked_archive(archive, lock, self.root / "output.tar", source_id)

    def test_unified_lock_rejects_duplicate_missing_and_extra_sources(self):
        lock = self.root / "source.json"
        entry = json.dumps(_package_locked("one", [_file("usr/bin/tool")])["sources"]["one"])
        lock.write_text('{"version":1,"sources":{"one":' + entry + ',"one":' + entry + '}}', encoding="utf-8")
        with self.assertRaises(ArchiveError):
            _load_source_lock(lock, "one")
        lock.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ArchiveError, "unsupported unified source lock"):
            validate_source_ids(lock, ["one"])
        lock.write_text(json.dumps(_package_locked("one", [_file("usr/bin/tool")])), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            validate_source_ids(lock, ["one", "missing"])
        with self.assertRaises(ArchiveError):
            validate_source_ids(lock, [])

    def test_rejects_duplicate_locked_path(self):
        entries = [_file("usr/bin/tool")]
        archive = self.root / "fixture.tar"
        archive.write_bytes(_tar_bytes(entries))
        source = _locked(entries, hashlib.sha256(archive.read_bytes()).hexdigest())
        source["files"].append(dict(source["files"][0]))
        lock = self.root / "source.json"
        lock.write_text(json.dumps(source), encoding="utf-8")
        with self.assertRaises(ArchiveError):
            extract_locked_archive(archive, lock, self.root / "output.tar")

    def test_lock_parser_rejects_non_objects_and_extra_keys(self):
        self.assert_lock_rejected([])
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        source["extra"] = True
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        source["files"] = ["not-an-object"]
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        source["files"][0]["extra"] = True
        self.assert_lock_rejected(source)

    def test_lock_parser_rejects_noncanonical_digests(self):
        source = _locked([_file("usr/bin/tool")], "A" * 64)
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        source["files"][0]["sha256"] = "G" * 64
        self.assert_lock_rejected(source)

    def test_lock_parser_rejects_wrong_type_fields(self):
        source = _locked([_symlink("usr/bin/tool", "target")], "0" * 64)
        source["files"][0]["sha256"] = "0" * 64
        source["files"][0]["size"] = 0
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        source["files"][0]["target"] = "tool"
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64)
        source["files"][0]["size"] = True
        self.assert_lock_rejected(source)

    def test_lock_parser_rejects_malformed_debian_shapes(self):
        source = _locked([_file("usr/bin/tool")], "0" * 64, kind="deb")
        source["control"]["extra"] = "value"
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64, kind="deb")
        source["unexpected"] = True
        self.assert_lock_rejected(source)

    def test_lock_parser_accepts_both_debian_optional_fields(self):
        source = _locked([_file("usr/share/vendor/tool")], "0" * 64, kind="deb")
        source["complete_directories"] = ["usr/share/vendor/"]
        source["control_dependency_exceptions"] = {"account-package": "fixed identity data"}
        lock = self.root / "source.json"
        lock.write_text(json.dumps(source), encoding="utf-8")
        self.assertEqual(_load_source_lock(lock)[0], "deb")

    def test_lock_parser_rejects_invalid_debian_selection(self):
        source = _locked([_file("usr/bin/tool")], "0" * 64, kind="deb")
        source["paths"] = ["usr/bin/tool", "usr/bin/tool"]
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64, kind="deb")
        source["paths"] = ["usr/bin/missing"]
        self.assert_lock_rejected(source)
        source = _locked([_file("usr/bin/tool")], "0" * 64, kind="deb")
        source["paths"] = ["usr/bin/selected"]
        source["complete_directories"] = ["usr/share/vendor/"]
        self.assert_lock_rejected(source)

    def test_ar_rejects_missing_noncanonical_padding_and_trailing_bytes(self):
        canonical = b"!<arch>\n" + _ar_member("odd", b"x")
        archive = self.root / "fixture.ar"
        archive.write_bytes(canonical[:-1])
        with self.assertRaises(ArchiveError):
            _ar_members(archive)
        archive.write_bytes(canonical[:-1] + b"X")
        with self.assertRaises(ArchiveError):
            _ar_members(archive)
        archive.write_bytes(canonical + b"\n")
        with self.assertRaises(ArchiveError):
            _ar_members(archive)

    def test_ar_size_requires_unsigned_decimal(self):
        archive = self.root / "fixture.ar"
        archive.write_bytes(b"!<arch>\n" + _ar_member_with_size("empty", b"0         "))
        self.assertEqual(_ar_members(archive), {"empty": b""})
        for size_field in (
            b"          ",
            b"-1        ",
            b"+1        ",
            b" 1        ",
            b"1 0       ",
            b"one       ",
        ):
            with self.subTest(size_field=size_field):
                archive.write_bytes(b"!<arch>\n" + _ar_member_with_size("bad", size_field, b"x"))
                with self.assertRaises(ArchiveError):
                    _ar_members(archive)

    def test_ar_rejects_oversized_or_truncated_member(self):
        archive = self.root / "fixture.ar"
        for size_field in (b"2         ", b"9999999999"):
            with self.subTest(size_field=size_field):
                archive.write_bytes(b"!<arch>\n" + _ar_member_with_size("bad", size_field, b"x"))
                with self.assertRaises(ArchiveError):
                    _ar_members(archive)


if __name__ == "__main__":
    unittest.main()
