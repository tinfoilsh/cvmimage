#!/usr/bin/env python3

import hashlib
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts import rootfs_artifacts


class RootfsArtifactsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.entries = {}
        for name, contract in rootfs_artifacts.EXPECTED.items():
            producer, kind, source_path, mode, target, destination, source_kind = contract
            digest = "-"
            if kind == "file":
                path = self.root / producer / source_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"fixture:{name}\n".encode())
                path.chmod(int(mode, 8))
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.entries[name] = rootfs_artifacts.Entry(
                producer, name, kind, source_path, mode, "0", "0", digest,
                target, destination, source_kind, "fixture:revision", "fixture=params",
            )
        self.lock = self.root / "lock.tsv"
        self.write(self.lock, self.entries.values())
        self.manifests = []
        for producer in sorted(rootfs_artifacts.PRODUCERS):
            manifest = self.root / producer / "rootfs-artifacts.tsv"
            self.write(manifest, (entry for entry in self.entries.values() if entry.producer == producer))
            self.manifests.append(f"{producer}={manifest}")

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def row(entry):
        return "\t".join(entry.__dict__.values())

    def write(self, path, entries):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n" + "\n".join(self.row(entry) for entry in entries) + "\n")

    def verify(self, lock=None, manifests=None):
        rootfs_artifacts.verify(lock or self.lock, manifests or self.manifests)

    def mutated_lock(self, artifact_name, **changes):
        entries = dict(self.entries)
        entries[artifact_name] = replace(entries[artifact_name], **changes)
        path = self.root / f"mutated-{artifact_name}.tsv"
        self.write(path, entries.values())
        return path

    def test_exact_contract_passes(self):
        source = self.root / "go/artifacts/tinfoil-init"
        if source.stat().st_uid == 0:
            os.chown(source, 65534, 65534)
        self.assertNotEqual(source.stat().st_uid, 0)
        self.verify()

    def test_rejects_missing_and_extra_artifacts(self):
        entries = dict(self.entries)
        del entries["tinfoil-shim"]
        self.write(self.lock, entries.values())
        with self.assertRaisesRegex(ValueError, "lock artifact set"):
            self.verify()
        self.write(self.lock, list(self.entries.values()) + [replace(self.entries["tinfoil-shim"], name="extra")])
        with self.assertRaisesRegex(ValueError, "fixed contract"):
            self.verify()

    def test_rejects_unmanifested_producer_file(self):
        extra = self.root / "go/artifacts/extra"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "unexpected or symlinked producer output"):
            self.verify()

    def test_rejects_symlinked_manifest(self):
        specification = self.manifests[0]
        producer, _, value = specification.partition("=")
        original = Path(value)
        link = original.with_name("linked-manifest.tsv")
        link.symlink_to(original.name)
        manifests = [f"{producer}={link}" if item == specification else item for item in self.manifests]
        with self.assertRaisesRegex(ValueError, "regular non-symlink file"):
            self.verify(manifests=manifests)

    def test_rejects_manifest_swap_after_read(self):
        manifest = Path(self.manifests[0].partition("=")[2])
        replacement = self.root / "replacement.tsv"
        replacement.write_bytes(manifest.read_bytes())
        original_verify_tree = rootfs_artifacts.verify_tree

        def swap_then_verify(*args):
            os.replace(replacement, manifest)
            return original_verify_tree(*args)

        with mock.patch.object(rootfs_artifacts, "verify_tree", side_effect=swap_then_verify):
            with self.assertRaisesRegex(ValueError, "manifest changed after reading"):
                self.verify()

    def test_rejects_symlinked_allowed_support_file(self):
        support = self.root / "go/artifacts.tsv"
        target = self.root / "support-target"
        target.write_text("target")
        support.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "unexpected or symlinked producer output"):
            self.verify()

    def test_rejects_unexpected_node_type(self):
        fifo = self.root / "go/artifacts.tsv"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "unexpected producer output type"):
            self.verify()

    def test_rejects_duplicate_name_and_destination(self):
        with self.lock.open("a") as output:
            output.write(self.row(self.entries["tinfoil-init"]) + "\n")
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            self.verify()
        self.write(self.lock, self.entries.values())
        bad = replace(self.entries["tinfoil-shim"], destination="/usr/bin/tinfoil-init")
        self.write(self.lock, [entry for name, entry in self.entries.items() if name != bad.name] + [bad])
        with self.assertRaisesRegex(ValueError, "fixed contract"):
            self.verify()

    def test_rejects_path_aliases_and_traversal(self):
        for source_path in ("artifacts/./tinfoil-init", "artifacts/../tinfoil-init", "/artifacts/tinfoil-init"):
            with self.subTest(source_path=source_path), self.assertRaises(ValueError):
                self.verify(self.mutated_lock("tinfoil-init", source_path=source_path))
        with self.assertRaises(ValueError):
            self.verify(self.mutated_lock("tinfoil-init", destination="/usr//bin/tinfoil-init"))
        with self.assertRaises(ValueError):
            self.verify(self.mutated_lock("tinfoil-init", destination="//usr/bin/tinfoil-init"))

    def test_rejects_symlink_parent_and_symlink_source(self):
        manifest = Path(self.manifests[0].partition("=")[2])
        producer = manifest.parent
        real = self.root / "real-artifacts"
        os.rename(producer / "artifacts", real)
        os.symlink(real, producer / "artifacts")
        with self.assertRaisesRegex(ValueError, "unexpected or symlinked producer output"):
            self.verify()

    def test_rejects_symlink_escape(self):
        with self.assertRaises(ValueError):
            self.verify(self.mutated_lock("libnvat.so.1", link_target="../escape"))

    def test_rejects_mode_hash_type_uid_gid_and_provenance_drift(self):
        mutations = (
            {"mode": "0644"},
            {"sha256": "0" * 64},
            {"kind": "symlink"},
            {"uid": "1"},
            {"gid": "1"},
            {"source_revision": "drift"},
        )
        for changes in mutations:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(self.mutated_lock("tinfoil-init", **changes))

    def test_rejects_missing_source_and_content_drift(self):
        source = self.root / "go/artifacts/tinfoil-init"
        source.unlink()
        with self.assertRaisesRegex(ValueError, "unsafe or missing source"):
            self.verify()
        source.write_bytes(b"changed")
        source.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "source hash mismatch"):
            self.verify()

    def test_rejects_source_xattrs(self):
        source = self.root / "go/artifacts/tinfoil-init"
        os.setxattr(source, "user.tinfoil-test", b"forbidden")
        with self.assertRaisesRegex(ValueError, "source xattrs are forbidden"):
            self.verify()

    def test_rejects_external_hardlinks(self):
        source = self.root / "go/artifacts/tinfoil-init"
        os.link(source, self.root / "external-hardlink")
        with self.assertRaisesRegex(ValueError, "external hardlinks are forbidden"):
            self.verify()

    def test_rejects_module_contract_drift(self):
        for changes in ({"mode": "0755"}, {"destination": "/usr/lib/modules/nvidia.ko"}, {"name": "nvidia-drm.ko"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(self.mutated_lock("nvidia.ko", **changes))


if __name__ == "__main__":
    unittest.main()
