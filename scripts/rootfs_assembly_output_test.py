#!/usr/bin/env python3

import argparse
import tarfile
import unittest
from pathlib import Path

from scripts import rootfs_manifest


class OutputContractTest(unittest.TestCase):
    archive = None
    manifest = None

    def test_exact_inventory_and_policy(self):
        entries = rootfs_manifest.parse_manifest(self.manifest)
        self.assertEqual(len(entries), 201)
        self.assertEqual(sum(entry.kind == "dir" for entry in entries.values()), 34)
        self.assertEqual(sum(entry.kind != "dir" for entry in entries.values()), 167)
        self.assertEqual(rootfs_manifest.policy_violations(entries), [])

    def test_exact_modules_and_explicit_absence(self):
        entries = rootfs_manifest.parse_manifest(self.manifest)
        modules = {path for path in entries if path.endswith((".ko", ".ko.xz", ".ko.zst"))}
        self.assertEqual(modules, rootfs_manifest.REQUIRED_MODULES)
        forbidden = (
            "/usr/lib/modules", "/etc/systemd", "/usr/lib/systemd", "/etc/sysctl.d",
            "/usr/lib/sysctl.d", "/etc/tmpfiles.d", "/usr/lib/tmpfiles.d", "/etc/tinfoil/templates",
            "/usr/share/tinfoil/templates", "/usr/bin/nvidia-smi", "/usr/bin/docker-init",
            "/usr/bin/nvidia-container-runtime-hook", "/etc/ld.so.cache", "/usr/sbin/iptables",
            "/usr/sbin/ip6tables", "/usr/sbin/xtables-nft-multi", "/bin/sh", "/usr/bin/sh",
        )
        for path in entries:
            self.assertFalse(any(path == item or path.startswith(item + "/") for item in forbidden), path)

    def test_archive_is_global_byte_ordered_ustar(self):
        entries = rootfs_manifest.parse_manifest(self.manifest)
        with tarfile.open(self.archive, "r:") as archive:
            members = archive.getmembers()
            paths = ["/" if member.name == "." else "/" + member.name for member in members]
            self.assertEqual(paths, sorted(entries, key=lambda path: path.encode()))
            self.assertEqual(set(paths), set(entries))
            for member in members:
                self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime), (0, 0, "", "", 0))
                self.assertEqual(member.pax_headers, {})


if __name__ == "__main__":
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--outputs", nargs=2, required=True)
    parsed, remaining = arguments.parse_known_args()
    outputs = {Path(path).suffix: Path(path) for path in parsed.outputs}
    OutputContractTest.archive = outputs[".tar"]
    OutputContractTest.manifest = outputs[".tsv"]
    unittest.main(argv=[__file__, *remaining])
