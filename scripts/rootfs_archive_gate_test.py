#!/usr/bin/env python3

import base64
import hashlib
import io
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import rootfs_archive_gate, rootfs_assembly, rootfs_manifest


def entry(path, kind, mode="0755", content="-"):
    return rootfs_manifest.Entry(path, kind, mode, "0", "0", content, "-", "-")


class ArchiveGateTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write_archive(self, members, format=tarfile.USTAR_FORMAT):
        path = self.root / f"archive-{len(list(self.root.glob('archive-*')))}.tar"
        with tarfile.open(path, "w", format=format) as archive:
            for specification in members:
                name, kind = specification[:2]
                value = specification[2] if len(specification) > 2 else None
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if kind == "dir" else 0o644
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                member.mtime = 0
                if kind == "dir":
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                elif kind == "file":
                    payload = value if isinstance(value, bytes) else b"payload"
                    member.type = tarfile.REGTYPE
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                elif kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.mode = 0o777
                    member.linkname = value
                    archive.addfile(member)
                elif kind == "hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = value
                    archive.addfile(member)
                elif kind == "fifo":
                    member.type = tarfile.FIFOTYPE
                    archive.addfile(member)
                elif kind == "owner":
                    member.type = tarfile.REGTYPE
                    member.uid = 1
                    member.size = 0
                    archive.addfile(member, io.BytesIO())
                elif kind == "pax":
                    member.type = tarfile.REGTYPE
                    member.pax_headers = {"SCHILY.xattr.user.test": "value"}
                    member.size = 0
                    archive.addfile(member, io.BytesIO())
                else:
                    raise AssertionError(kind)
        path.chmod(0o644)
        return path

    def fixed_expected(self, payload=b"payload"):
        digest = hashlib.sha256(payload).hexdigest()
        target = base64.b64encode(b"file").decode()
        entries = [
            entry("/", "dir"),
            entry("/dir", "dir"),
            entry("/dir/file", "file", "0644", "sha256:" + digest),
            entry("/link", "symlink", "0777", "target64:" + target),
        ]
        return {item.path: item for item in entries}

    def fixed_archive(self, payload=b"payload"):
        return self.write_archive(
            [(".", "dir"), ("dir", "dir"), ("dir/file", "file", payload), ("link", "symlink", "file")]
        )

    def materialize(self, archive, destination, expected):
        with rootfs_assembly.checked_descriptor(archive) as (descriptor, _):
            rootfs_archive_gate.materialize(descriptor, destination, expected)

    def verify_locked_archive(self, descriptor, locked_digest, expected):
        with mock.patch.object(rootfs_manifest, "policy_violations", return_value=[]):
            rootfs_archive_gate.verify_locked_archive(descriptor, locked_digest, expected)

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_materializes_and_inventories_bidirectionally(self):
        expected = self.fixed_expected()
        destination = self.root / "realized"
        self.materialize(self.fixed_archive(), destination, expected)
        actual = {item.path: item for item in rootfs_manifest.Inventory(destination).collect()}
        self.assertEqual(rootfs_manifest.compare_manifests(expected, actual), [])

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_missing_extra_content_mode_owner_and_link_mutations_fail(self):
        cases = [
            ([(".", "dir"), ("dir", "dir"), ("link", "symlink", "file")], "inventory"),
            ([(".", "dir"), ("dir", "dir"), ("dir/file", "file"), ("extra", "file"), ("link", "symlink", "file")], "unexpected"),
            ([(".", "dir"), ("dir", "dir"), ("dir/file", "file", b"changed"), ("link", "symlink", "file")], "content"),
            ([(".", "dir"), ("dir", "dir"), ("dir/file", "file"), ("link", "symlink", "wrong")], "symlink"),
            ([(".", "dir"), ("dir", "dir"), ("dir/file", "owner"), ("link", "symlink", "file")], "ownership"),
        ]
        for members, message in cases:
            destination = self.root / ("failed-" + message)
            with self.subTest(message=message), self.assertRaisesRegex(rootfs_archive_gate.GateError, message):
                self.materialize(self.write_archive(members), destination, self.fixed_expected())
            self.assertFalse(destination.exists())
        mode_archive = self.write_archive(
            [(".", "dir"), ("dir", "dir"), ("dir/file", "file"), ("link", "symlink", "file")]
        )
        data = bytearray(mode_archive.read_bytes())
        data[2 * 512 + 100 : 2 * 512 + 108] = b"0000600\0"
        data[2 * 512 + 148 : 2 * 512 + 156] = b"        "
        checksum = sum(data[2 * 512 : 3 * 512])
        data[2 * 512 + 148 : 2 * 512 + 156] = f"{checksum:06o}\0 ".encode()
        mode_archive.write_bytes(data)
        with self.assertRaisesRegex(rootfs_archive_gate.GateError, "mode"):
            self.materialize(mode_archive, self.root / "failed-mode", self.fixed_expected())

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_hardlink_special_xattr_and_path_forms_fail_without_residue(self):
        cases = [
            ([(".", "dir"), ("dir", "dir"), ("dir/file", "hardlink", "dir/file"), ("link", "symlink", "file")], "hardlinks"),
            ([(".", "dir"), ("dir", "dir"), ("dir/file", "fifo"), ("link", "symlink", "file")], "type"),
            ([(".", "dir"), ("dir", "dir"), ("dir/file", "pax"), ("link", "symlink", "file")], "extended"),
            ([(".", "dir"), ("dir", "dir"), ("../escape", "file"), ("link", "symlink", "file")], "canonical"),
            ([(".", "dir"), ("dir", "dir"), ("./dir/file", "file"), ("link", "symlink", "file")], "canonical"),
        ]
        for members, message in cases:
            destination = self.root / ("rejected-" + str(len(list(self.root.glob("rejected-*")))))
            with self.subTest(message=message), self.assertRaises((rootfs_archive_gate.GateError, ValueError)):
                self.materialize(
                    self.write_archive(members, tarfile.PAX_FORMAT if message == "extended" else tarfile.USTAR_FORMAT),
                    destination,
                    self.fixed_expected(),
                )
            self.assertFalse(destination.exists())

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_non_ustar_archive_fails_before_materialization(self):
        archive = self.write_archive(
            [(".", "dir"), ("dir", "dir"), ("dir/file", "file"), ("link", "symlink", "file")],
            format=tarfile.GNU_FORMAT,
        )
        locked_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        with mock.patch.object(rootfs_archive_gate, "materialize") as materialize:
            with self.assertRaisesRegex(rootfs_archive_gate.GateError, "POSIX USTAR"):
                with rootfs_archive_gate.checked_archive_descriptor(archive) as descriptor:
                    self.verify_locked_archive(descriptor, locked_digest, self.fixed_expected())
            materialize.assert_not_called()

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_realized_policy_failure_is_final(self):
        archive = self.fixed_archive()
        locked_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        with mock.patch.object(
            rootfs_manifest,
            "policy_violations",
            return_value=[("/", "adversarial realized policy failure")],
        ):
            with self.assertRaisesRegex(rootfs_archive_gate.GateError, "materialized rootfs inventory violates fixed policy"):
                with rootfs_archive_gate.checked_archive_descriptor(archive) as descriptor:
                    rootfs_archive_gate.verify_locked_archive(descriptor, locked_digest, self.fixed_expected())

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_symlink_ancestor_escape_and_stale_root_fail_closed(self):
        target = base64.b64encode(b"dir").decode()
        expected = {
            item.path: item
            for item in [
                entry("/", "dir"),
                entry("/dir", "dir"),
                entry("/ancestor", "symlink", "0777", "target64:" + target),
                entry("/ancestor/file", "file", "0644", "sha256:" + hashlib.sha256(b"payload").hexdigest()),
            ]
        }
        archive = self.write_archive(
            [(".", "dir"), ("dir", "dir"), ("ancestor", "symlink", "dir"), ("ancestor/file", "file")]
        )
        destination = self.root / "escape"
        with self.assertRaises((rootfs_archive_gate.GateError, ValueError)):
            self.materialize(archive, destination, expected)
        self.assertFalse(destination.exists())
        stale = self.root / "stale"
        stale.mkdir()
        (stale / "owned").write_text("keep")
        with self.assertRaises(FileExistsError):
            self.materialize(self.fixed_archive(), stale, self.fixed_expected())
        self.assertEqual((stale / "owned").read_text(), "keep")

    def test_archive_lock_and_manifest_drift_fail_before_materialization(self):
        expected = Path("image/manifests/rootfs.expected.tsv").read_bytes()
        expected_path = self.root / "expected.tsv"
        expected_path.write_bytes(expected)
        expected_path.chmod(0o644)
        generated = self.root / "generated.tsv"
        generated.write_bytes(expected + b"drift")
        generated.chmod(0o644)
        archive = self.root / "rootfs.tar"
        archive.write_bytes(b"archive")
        archive.chmod(0o644)
        lock = self.root / "archive.sha256"
        lock.write_text("0" * 64 + "\n")
        lock.chmod(0o644)
        with self.assertRaisesRegex(rootfs_archive_gate.GateError, "byte-identical"):
            rootfs_archive_gate.verify(archive, generated, expected_path, lock)
        generated.write_bytes(expected)
        with self.assertRaisesRegex(rootfs_archive_gate.GateError, "archive bytes"):
            rootfs_archive_gate.verify(archive, generated, expected_path, lock)

    def test_noncanonical_complete_archive_consumption_fails(self):
        expected = list(self.fixed_expected().values())
        original = self.fixed_archive().read_bytes()
        cases = {
            "length differs": original + original,
            "length differs trailing": original + b"garbage",
            "non-zero trailer": original[:-1] + b"x",
        }
        for message, content in cases.items():
            archive = self.root / (message.replace(" ", "-") + ".tar")
            archive.write_bytes(content)
            archive.chmod(0o644)
            with self.subTest(message=message), self.assertRaisesRegex(
                rootfs_assembly.AssemblyError,
                message.removesuffix(" trailing"),
            ):
                with rootfs_assembly.checked_descriptor(archive) as (descriptor, _):
                    rootfs_archive_gate.verify_archive(descriptor, expected)

        padded = bytearray(original)
        payload_offset = tarfile.BLOCKSIZE * 3
        padded[payload_offset + len(b"payload")] = 1
        archive = self.root / "noncanonical-member-padding.tar"
        archive.write_bytes(padded)
        archive.chmod(0o644)
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "member padding"):
            with rootfs_assembly.checked_descriptor(archive) as (descriptor, _):
                rootfs_archive_gate.verify_archive(descriptor, expected)

    def test_policy_failure_precedes_archive_and_materialization(self):
        expected_path = Path("image/manifests/rootfs.expected.tsv")
        mutated = expected_path.read_bytes().replace(b"/dev\tdir\t0755", b"/dev\tdir\t0777", 1)
        expected = self.root / "expected.tsv"
        generated = self.root / "generated.tsv"
        for path in (expected, generated):
            path.write_bytes(mutated)
            path.chmod(0o644)
        archive = self.root / "rootfs.tar"
        archive.write_bytes(b"archive")
        archive.chmod(0o644)
        lock = self.root / "archive.sha256"
        lock.write_text(hashlib.sha256(b"archive").hexdigest() + "\n")
        lock.chmod(0o644)
        with mock.patch.object(rootfs_archive_gate, "materialize") as materialize:
            with self.assertRaisesRegex(rootfs_archive_gate.GateError, "policy"):
                rootfs_archive_gate.verify(archive, generated, expected, lock)
            materialize.assert_not_called()

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_path_replacement_between_phases_fails_closed(self):
        expected = self.fixed_expected()
        for phase in ("archive_digest", "verify_archive"):
            archive = self.fixed_archive()
            original = archive.read_bytes()
            replacement = self.fixed_archive(b"replacement")
            replacement_bytes = replacement.read_bytes()
            locked_digest = hashlib.sha256(original).hexdigest()
            implementation = getattr(rootfs_archive_gate, phase)

            def replace_path(*arguments, implementation=implementation):
                result = implementation(*arguments)
                os.replace(replacement, archive)
                return result

            with self.subTest(phase=phase):
                with self.assertRaisesRegex(rootfs_archive_gate.GateError, "changed while being verified"):
                    with rootfs_archive_gate.checked_archive_descriptor(archive) as descriptor:
                        with mock.patch.object(rootfs_archive_gate, phase, side_effect=replace_path):
                            self.verify_locked_archive(descriptor, locked_digest, expected)
                self.assertEqual(archive.read_bytes(), replacement_bytes)

    @unittest.skipUnless(os.geteuid() == 0, "faithful ownership test requires UID 0")
    def test_final_descriptor_identity_change_fails_closed(self):
        archive = self.fixed_archive()
        locked_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(rootfs_archive_gate.GateError, "changed while being verified"):
            with rootfs_archive_gate.checked_archive_descriptor(archive) as descriptor:
                self.verify_locked_archive(descriptor, locked_digest, self.fixed_expected())
                os.fchmod(descriptor, 0o600)

    def test_non_root_materialization_has_no_ownership_fallback(self):
        with mock.patch("os.geteuid", return_value=1000):
            archive = self.fixed_archive()
            with rootfs_assembly.checked_descriptor(archive) as (descriptor, _):
                with self.assertRaisesRegex(rootfs_archive_gate.GateError, "no ownership fallback"):
                    rootfs_archive_gate.materialize(descriptor, self.root / "non-root", self.fixed_expected())


if __name__ == "__main__":
    unittest.main()
