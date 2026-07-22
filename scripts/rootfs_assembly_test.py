#!/usr/bin/env python3

import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts import rootfs_assembly


class RootfsAssemblyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, name="member", content=b"payload", kind=tarfile.REGTYPE, pax=None):
        path = self.root / "input.tar"
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT if pax else tarfile.GNU_FORMAT) as archive:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.uid = member.gid = 0
            member.uname = member.gname = "root"
            member.mtime = 0
            member.type = kind
            member.pax_headers = pax or {}
            if kind == tarfile.REGTYPE:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            else:
                archive.addfile(member)
        return path

    def locked(self, content=b"payload"):
        return {"member": ("file", "0644", hashlib.sha256(content).hexdigest(), len(content), "-")}

    def test_fixed_input_cardinality(self):
        self.assertEqual(len(rootfs_assembly.PACKAGE_IDS), 35)
        self.assertEqual(len(rootfs_assembly.VENDOR_IDS), 11)
        self.assertEqual(len(rootfs_assembly.CONFIG_PATHS), 12)

    def test_duplicate_destination_fails_even_when_identical(self):
        entries = {}
        entry = rootfs_assembly.Entry("/same", "file", "0644", "0" * 64)
        rootfs_assembly.add(entries, entry)
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "duplicate"):
            rootfs_assembly.add(entries, entry)

    def test_non_directory_ancestor_fails(self):
        entries = {"/parent": rootfs_assembly.Entry("/parent", "symlink", "0777", link="target")}
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "ancestor"):
            rootfs_assembly.add(entries, rootfs_assembly.Entry("/parent/child", "file", "0644"))

    def test_archive_content_mutation_fails(self):
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "content differs"):
            rootfs_assembly.inspect_member_archive(self.archive(content=b"changed"), self.locked())

    def test_archive_missing_and_extra_members_fail(self):
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "inventory differs"):
            rootfs_assembly.inspect_member_archive(self.archive(), {**self.locked(), "other": self.locked()["member"]})
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "differs from lock"):
            rootfs_assembly.inspect_member_archive(self.archive(name="extra"), self.locked())

    def test_concatenated_tar_archive_fails(self):
        archive = self.archive()
        archive.write_bytes(archive.read_bytes() * 2)
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "length differs"):
            rootfs_assembly.inspect_member_archive(archive, self.locked())

    def test_trailing_archive_garbage_fails(self):
        archive = self.archive()
        archive.write_bytes(archive.read_bytes() + b"garbage")
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "length differs"):
            rootfs_assembly.inspect_member_archive(archive, self.locked())

    def test_nonzero_archive_trailer_fails(self):
        archive = self.archive()
        data = bytearray(archive.read_bytes())
        data[-1] = 1
        archive.write_bytes(data)
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "non-zero trailer"):
            rootfs_assembly.inspect_member_archive(archive, self.locked())

    def test_bazel_sandbox_absolute_input_symlink_is_accepted(self):
        source = self.root / "source"
        source.write_bytes(b"payload")
        sandbox = self.root / "sandbox" / "execroot"
        sandbox.mkdir(parents=True)
        (sandbox / "input").symlink_to(source)
        previous = Path.cwd()
        try:
            os.chdir(sandbox)
            self.assertEqual(rootfs_assembly.checked_bytes(Path("input")), b"payload")
        finally:
            os.chdir(previous)

    def test_forbidden_tar_types_fail(self):
        for kind in (tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaisesRegex(rootfs_assembly.AssemblyError, "forbidden"):
                rootfs_assembly.inspect_member_archive(self.archive(kind=kind), self.locked())

    def test_pax_and_xattr_metadata_fails(self):
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "invalid or duplicate"):
            rootfs_assembly.inspect_member_archive(self.archive(pax={"SCHILY.xattr.user.test": "value"}), self.locked())

    def test_traversal_and_absolute_members_fail(self):
        for name in ("../escape", "/absolute", "a//b", "./alias"):
            with self.subTest(name=name), self.assertRaises(rootfs_assembly.AssemblyError):
                rootfs_assembly.inspect_member_archive(self.archive(name=name), self.locked())

    def test_source_set_missing_and_extra_fail_before_archive_access(self):
        package_lock = {"version": 1, "sources": {source_id: {"files": []} for source_id in rootfs_assembly.PACKAGE_IDS}}
        package_inputs = [(source_id, "missing") for source_id in rootfs_assembly.PACKAGE_IDS]
        for mutation in (lambda value: value[:-1], lambda value: value + [("extra", "missing")]):
            with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "source order"):
                rootfs_assembly.archive_entries(mutation(package_inputs), package_lock, True)
        package_lock["sources"]["extra"] = {"files": []}
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "source set"):
            rootfs_assembly.archive_entries(package_inputs, package_lock, True)

    def test_config_symlink_and_content_mutation_fail(self):
        source = self.root / "config"
        source.write_bytes(b"fixed")
        source.chmod(0o644)
        lock = self.root / "policy"
        digest = hashlib.sha256(b"fixed").hexdigest()
        lock.write_text("".join(f"{digest}  {path}\n" for path in rootfs_assembly.CONFIG_PATHS))
        inputs = [(path, source) for path in rootfs_assembly.CONFIG_PATHS]
        self.assertEqual(len(rootfs_assembly.config_entries(inputs, lock)), 12)
        source.write_bytes(b"mutated")
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "hash differs"):
            rootfs_assembly.config_entries(inputs, lock)
        source.write_bytes(b"fixed")
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "configuration differs"):
            rootfs_assembly.config_entries(inputs[:-1], lock)
        link = self.root / "link"
        link.symlink_to(source)
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "unsafe input path"):
            rootfs_assembly.checked_bytes(link)

    def test_lock_metadata_must_be_canonical(self):
        base = {"path": "member", "type": "file", "mode": "0644", "sha256": "a" * 64, "size": 1}
        for field, value in (("mode", "644"), ("mode", "0688"), ("sha256", "A" * 64), ("size", -1), ("size", True)):
            mutated = {**base, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(rootfs_assembly.AssemblyError):
                rootfs_assembly.lock_entries([mutated])
        with self.assertRaises(rootfs_assembly.AssemblyError):
            rootfs_assembly.lock_entries([{"path": "link", "type": "symlink", "mode": "0777", "target": "../../escape"}])

    def test_vendor_arguments_and_source_set_are_exact(self):
        sources = [{"id": source_id, "files": []} for source_id in (*rootfs_assembly.VENDOR_IDS, "nvidia-container-toolkit")]
        lock = {"version": 1, "sources": sources}
        inputs = [(source_id, "missing") for source_id in rootfs_assembly.VENDOR_IDS]
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "source order"):
            rootfs_assembly.archive_entries(inputs[:-1], lock, False)
        lock["sources"] = sources[:-1]
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "source set"):
            rootfs_assembly.archive_entries(inputs, lock, False)

    def test_runtime_archive_manifest_mutations_fail(self):
        archive = Path("image/runtime-artifact-members.tar")
        manifest = Path("image/runtime-artifact-members.tsv")
        lock = Path("image/manifests/rootfs-artifacts.lock.tsv")
        if not archive.exists():
            self.skipTest("runtime artifact inputs are provided by Bazel integration")
        self.assertEqual(len(rootfs_assembly.runtime_entries(archive, manifest, lock)), 12)
        mutated_manifest = self.root / "runtime.tsv"
        text = manifest.read_text()
        mutated_manifest.write_text(text.replace("sha256:", "sha256:0", 1))
        mutated_manifest.chmod(0o644)
        with self.assertRaises(ValueError):
            rootfs_assembly.runtime_entries(archive, mutated_manifest, lock)
        mutated_archive = self.root / "runtime.tar"
        data = bytearray(archive.read_bytes())
        with tarfile.open(archive, "r:") as bundle:
            member = next(member for member in bundle.getmembers() if member.isfile())
            data[member.offset_data] ^= 1
        mutated_archive.write_bytes(data)
        mutated_archive.chmod(0o644)
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "content differs"):
            rootfs_assembly.runtime_entries(mutated_archive, manifest, lock)
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "unsafe input"):
            rootfs_assembly.runtime_entries(self.root / "missing.tar", manifest, lock)

    def test_fabricmanager_hash_occurrence_and_diff(self):
        content = self.real_fabricmanager()
        transformed = rootfs_assembly.transform_fabricmanager(content)
        self.assertEqual(hashlib.sha256(transformed).hexdigest(), rootfs_assembly.FM_OUTPUT)
        self.assertEqual(content.replace(rootfs_assembly.FM_BEFORE, rootfs_assembly.FM_AFTER), transformed)
        for mutation in (content + b"x", content.replace(rootfs_assembly.FM_BEFORE, b"")):
            with self.assertRaises(rootfs_assembly.AssemblyError):
                rootfs_assembly.transform_fabricmanager(mutation)

    def real_fabricmanager(self):
        lock = json.loads(Path("image/runtime-sources.lock.json").read_text())
        source = next(source for source in lock["sources"] if source["id"] == "nvidia-fabricmanager")
        entry = next(entry for entry in source["files"] if entry["path"] == rootfs_assembly.FM_PATH[1:])
        self.assertEqual(entry["sha256"], rootfs_assembly.FM_INPUT)
        archive = Path("image") / "nvidia_fabricmanager-members.tar"
        if not archive.exists():
            self.skipTest("focused source archive is provided by Bazel integration")
        with tarfile.open(archive, "r:") as bundle:
            return bundle.extractfile(bundle.getmember(entry["path"])).read()

    def test_failure_before_publication_leaves_no_outputs(self):
        output_tar, output_manifest = self.root / "out.tar", self.root / "out.tsv"
        with self.assertRaisesRegex(rootfs_assembly.AssemblyError, "policy"):
            rootfs_assembly.write_outputs({"/": rootfs_assembly.Entry("/", "dir", "0755")}, output_tar, output_manifest)
        self.assertFalse(output_tar.exists())
        self.assertFalse(output_manifest.exists())


if __name__ == "__main__":
    unittest.main()
