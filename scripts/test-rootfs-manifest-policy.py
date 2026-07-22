#!/usr/bin/env python3

import importlib.util
import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts/rootfs_manifest.py"
SPEC = importlib.util.spec_from_file_location("rootfs_manifest", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

DIGEST = "sha256:" + "0" * 64
MODULE_PATHS = (
    "/usr/lib/tinfoil/kernel-modules/nvidia-modeset.ko",
    "/usr/lib/tinfoil/kernel-modules/nvidia-uvm.ko",
    "/usr/lib/tinfoil/kernel-modules/nvidia.ko",
)


def entry(path, kind="file", mode=None, uid="0", gid="0", xattrs="-"):
    if mode is None:
        mode = "0755" if kind == "dir" else "0777" if kind == "symlink" else "0644"
    content = DIGEST if kind == "file" else "target64:dGFyZ2V0" if kind == "symlink" else "-"
    if kind in {"char", "block"}:
        content = "dev:1:3"
    return MODULE.Entry(path, kind, mode, uid, gid, content, xattrs, "-")


def minimal_entries():
    entries = {
        "/": entry("/", "dir"),
        "/dev": entry("/dev", "dir"),
        "/proc": entry("/proc", "dir"),
        "/run": entry("/run", "dir"),
        "/sys": entry("/sys", "dir"),
        "/tmp": entry("/tmp", "dir"),
        "/var/tmp": entry("/var/tmp", "dir"),
    }
    entries.update({path: entry(path) for path in MODULE_PATHS})
    return entries


def full_entries():
    entries = minimal_entries()
    for path in (
        "/etc",
        "/mnt",
        "/mnt/ramdisk",
        "/usr",
        "/usr/lib",
        "/usr/lib/tinfoil",
        "/usr/lib/tinfoil/kernel-modules",
        "/var",
        "/var/lib",
        "/var/lib/containerd",
        "/var/lib/docker",
    ):
        entries[path] = entry(path, "dir")
    entries["/etc/hosts"] = entry(
        "/etc/hosts", xattrs=json.dumps({"user.note": "b2s="}, separators=(",", ":"))
    )
    return entries


def write_manifest(directory, entries, name="manifest.tsv"):
    path = Path(directory, name)
    ordered = sorted(entries.values(), key=lambda item: item.path.encode("utf-8"))
    path.write_bytes(MODULE.serialize(ordered))
    return path


class PolicyTests(unittest.TestCase):
    def assert_rejected(self, entries, expected_path):
        violations = MODULE.policy_violations(entries)
        self.assertTrue(violations)
        self.assertIn(expected_path, {path for path, _ in violations})

    def test_valid_minimal_and_full_manifests(self):
        with tempfile.TemporaryDirectory() as scratch:
            for name, entries in (("minimal", minimal_entries()), ("full", full_entries())):
                with self.subTest(name=name):
                    path = write_manifest(scratch, entries, name + ".tsv")
                    parsed = MODULE.parse_manifest(path)
                    self.assertEqual([], MODULE.policy_violations(parsed))
                    result = subprocess.run([TOOL, "policy", path], capture_output=True, text=True)
                    self.assertEqual(0, result.returncode, result.stderr)

    def test_world_writable_non_symlink_is_rejected(self):
        entries = minimal_entries()
        entries["/opt/data"] = entry("/opt/data", mode="0666")
        self.assert_rejected(entries, "/opt/data")
        entries["/opt/data"] = entry("/opt/data", "symlink", mode="0777")
        self.assertEqual([], MODULE.policy_violations(entries))

    def test_all_special_permission_bits_are_rejected(self):
        for mode in ("4644", "2644", "1755"):
            with self.subTest(mode=mode):
                entries = minimal_entries()
                entries["/opt/privileged"] = entry("/opt/privileged", mode=mode)
                self.assert_rejected(entries, "/opt/privileged")

    def test_capability_representations_are_rejected(self):
        for name in ("security.capability", "trusted.file-capability"):
            with self.subTest(name=name):
                entries = minimal_entries()
                xattrs = json.dumps({name: "AA=="}, separators=(",", ":"))
                entries["/opt/tool"] = entry("/opt/tool", xattrs=xattrs)
                self.assert_rejected(entries, "/opt/tool")

    def test_every_special_object_type_is_rejected(self):
        for kind in ("char", "block", "fifo", "socket"):
            with self.subTest(kind=kind):
                entries = minimal_entries()
                entries["/opt/special"] = entry("/opt/special", kind)
                self.assert_rejected(entries, "/opt/special")

    def test_kernel_module_boundaries_are_rejected(self):
        cases = (
            "/usr/lib/modules",
            "/usr/lib/modules/6.0/kernel/stock.ko",
            "/opt/nvidia.ko",
            "/opt/nvidia.ko.zst",
            "/usr/lib/tinfoil/kernel-modules/nvidia-drm.ko",
            "/usr/lib/tinfoil/kernel-modules/nvidia.ko.zst",
        )
        for path in cases:
            with self.subTest(path=path):
                entries = minimal_entries()
                entries[path] = entry(path, "dir" if path == "/usr/lib/modules" else "file")
                self.assert_rejected(entries, path)

    def test_exact_module_contract_is_required(self):
        entries = minimal_entries()
        del entries[MODULE_PATHS[0]]
        self.assert_rejected(entries, MODULE_PATHS[0])
        for changes in (
            {"kind": "dir", "content": "-"},
            {"mode": "0600"},
            {"uid": "1"},
            {"gid": "1"},
            {"xattrs": '{"user.note":"b2s="}'},
            {
                "hardlink": (
                    "path64:L3Vzci9saWIvdGluZm9pbC9rZXJuZWwtbW9kdWxlcy8"
                    "udmlkaWEtbW9kZXNldC5rbw=="
                )
            },
        ):
            with self.subTest(changes=changes):
                entries = minimal_entries()
                entries[MODULE_PATHS[0]] = replace(entries[MODULE_PATHS[0]], **changes)
                self.assert_rejected(entries, MODULE_PATHS[0])

    def test_forbidden_fixed_contract_categories(self):
        cases = {
            "shell-sh": "/bin/sh",
            "shell-bash": "/usr/bin/bash",
            "systemd-policy": "/etc/systemd/system/example.service",
            "systemd-tool": "/usr/bin/systemctl",
            "sysctl-policy": "/etc/sysctl.d/99-example.conf",
            "tmpfiles-policy": "/usr/lib/tmpfiles.d/example.conf",
            "ld-cache": "/etc/ld.so.cache",
            "ld-config": "/etc/ld.so.conf.d/example.conf",
            "ld-tool": "/usr/sbin/ldconfig",
            "nvidia-smi": "/usr/bin/nvidia-smi",
            "docker-init": "/usr/libexec/docker/docker-init",
            "chat-template": "/etc/tinfoil/templates/tool_chat_template.jinja",
            "var-log": "/var/log/messages",
            "root-home": "/root/secret",
            "user-home": "/home/user/data",
            "boot": "/boot/vmlinuz",
            "efi": "/EFI/BOOT/BOOTX64.EFI",
            "apt-metadata": "/var/lib/apt/lists/index",
            "dpkg-metadata": "/var/lib/dpkg/status",
            "package-tool": "/usr/bin/apt-get",
        }
        for name, path in cases.items():
            with self.subTest(name=name):
                entries = minimal_entries()
                entries[path] = entry(path)
                self.assert_rejected(entries, path)

    def test_runtime_state_must_not_be_shipped(self):
        for path in (
            "/dev/precreated",
            "/proc/precreated",
            "/run/service.pid",
            "/sys/precreated",
            "/tmp/precreated",
            "/var/tmp/precreated",
            "/mnt/ramdisk/private/key",
            "/var/lib/containerd/state",
            "/var/lib/docker/containers",
        ):
            with self.subTest(path=path):
                entries = full_entries()
                entries[path] = entry(path)
                self.assert_rejected(entries, path)
        entries = minimal_entries()
        entries["/run"] = entry("/run")
        self.assert_rejected(entries, "/run")

    def test_kernel_mountpoints_are_required_empty_root_owned_0755_directories(self):
        for path in ("/dev", "/proc", "/run", "/sys"):
            with self.subTest(path=path, case="missing"):
                entries = minimal_entries()
                del entries[path]
                self.assert_rejected(entries, path)
            changesets = (
                {"mode": "0700"},
                {"uid": "1"},
                {"gid": "1"},
                {"kind": "file", "content": DIGEST},
            )
            for changes in changesets:
                with self.subTest(path=path, changes=changes):
                    entries = minimal_entries()
                    entries[path] = replace(entries[path], **changes)
                    self.assert_rejected(entries, path)

    def test_tmp_mountpoints_are_mandatory_root_owned_0755_directories(self):
        for path in ("/tmp", "/var/tmp"):
            entries = minimal_entries()
            del entries[path]
            self.assert_rejected(entries, path)
            for changes in ({"mode": "0700"}, {"uid": "1"}, {"gid": "1"}, {"mode": "1755"}):
                with self.subTest(path=path, changes=changes):
                    entries = minimal_entries()
                    entries[path] = replace(entries[path], **changes)
                    self.assert_rejected(entries, path)

    def test_path_checks_use_exact_component_semantics(self):
        entries = minimal_entries()
        entries["/homeward"] = entry("/homeward", "dir")
        entries["/usr/lib/modules-extra"] = entry("/usr/lib/modules-extra", "dir")
        entries["/usr/bin/bashful"] = entry("/usr/bin/bashful")
        entries["/var/logger"] = entry("/var/logger", "dir")
        self.assertEqual([], MODULE.policy_violations(entries))

    def test_malformed_manifest_fails_before_policy_evaluation(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch, "malformed.tsv")
            path.write_text("/\tdir\t0755\t0\t0\t-\t-\n")
            result = subprocess.run([TOOL, "policy", path], capture_output=True, text=True)
            self.assertEqual(2, result.returncode)
            self.assertIn("expected exactly eight tab-separated fields", result.stderr)
            self.assertNotIn("policy\t", result.stderr)


if __name__ == "__main__":
    unittest.main()
