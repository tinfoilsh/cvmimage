import contextlib
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.runtime_archive import ArchiveError
from scripts.update_runtime_package_members import _bazel, main, update


def _archive(path, data=b"payload"):
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        member = tarfile.TarInfo("./usr/bin/tool")
        member.mode = 0o755
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))


def _lock(data=b"payload"):
    return {
        "version": 1,
        "sources": {
            "tool_1_amd64": {
                "files": [{
                    "gid": 0,
                    "mode": "0755",
                    "path": "usr/bin/tool",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "type": "file",
                    "uid": 0,
                    "xattrs": {},
                }],
                "kind": "tar",
                "package_data": True,
            },
        },
    }


def _package_lock(source_id="tool_1_amd64", name="tool", version="1", arch="amd64"):
    return {
        "version": 1,
        "packages": [{
            "arch": arch,
            "key": source_id,
            "name": name,
            "version": version,
        }],
    }


class UpdateRuntimePackageMembersTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.lock = self.root / "lock.json"
        self.lock.write_text(json.dumps(_lock(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        image = self.root / "image"
        image.mkdir()
        self.package_lock = image / "runtime-packages.lock.json"
        self.package_lock.write_text(
            json.dumps(_package_lock(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.calls = []

    def tearDown(self):
        self.directory.cleanup()

    def resolver(self, _workspace, output_root):
        self.calls.append(output_root)
        output_root.mkdir(parents=True)
        archive = output_root / "package.tar"
        _archive(archive)
        return {"tool_1_amd64": archive}

    @mock.patch("scripts.update_runtime_package_members.subprocess.run")
    def test_bazel_disables_worktree_convenience_symlinks(self, run):
        run.return_value.stdout = ""
        _bazel(self.root, self.root / "output", "build", "//image:target")
        command = run.call_args.args[0]
        self.assertEqual(command[3:6], ["build", "--symlink_prefix=/", "--lockfile_mode=error"])
        self.assertIn(f"--output_user_root={self.root / 'output'}", command)

    @mock.patch.dict("os.environ", {"BAZEL": "/trusted/bazel"})
    @mock.patch("scripts.update_runtime_package_members.subprocess.run")
    def test_bazel_honors_selected_binary(self, run):
        run.return_value.stdout = ""
        _bazel(self.root, self.root / "output", "build", "//image:target")
        self.assertEqual(run.call_args.args[0][0], "/trusted/bazel")

    def test_check_resolves_twice_and_does_not_write(self):
        before = self.lock.read_bytes()
        update(self.root, self.lock, check=True, resolver=self.resolver)
        self.assertEqual(self.lock.read_bytes(), before)
        self.assertEqual(len(self.calls), 2)
        self.assertNotEqual(self.calls[0], self.calls[1])

    def test_stale_check_does_not_write(self):
        stale = _lock(b"stale")
        self.lock.write_text(json.dumps(stale, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        before = self.lock.read_bytes()
        with self.assertRaises(ArchiveError):
            update(self.root, self.lock, check=True, resolver=self.resolver)
        self.assertEqual(self.lock.read_bytes(), before)

    def test_rejects_nonidentical_resolutions(self):
        calls = 0

        def resolver(_workspace, output_root):
            nonlocal calls
            calls += 1
            output_root.mkdir(parents=True)
            archive = output_root / "package.tar"
            _archive(archive, b"first" if calls == 1 else b"second")
            return {"tool_1_amd64": archive}

        with self.assertRaises(ArchiveError):
            update(self.root, self.lock, check=True, resolver=resolver)

    def test_rejects_stale_package_identity(self):
        self.package_lock.write_text(
            json.dumps(_package_lock("tool_2_amd64", version="2")),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArchiveError, "stale or unknown"):
            update(self.root, self.lock, check=True, resolver=self.resolver)

    def test_rejects_package_key_that_mismatches_identity(self):
        self.package_lock.write_text(
            json.dumps(_package_lock("tool_1_amd64", version="2")),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArchiveError, "does not match"):
            update(self.root, self.lock, check=True, resolver=self.resolver)

    @mock.patch("scripts.update_runtime_package_members.update", side_effect=tarfile.ReadError("bad tar"))
    @mock.patch("sys.argv", ["update_runtime_package_members.py"])
    def test_main_reports_tar_errors_without_traceback(self, _update):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit):
            main()
        self.assertEqual(errors.getvalue(), "update_runtime_package_members.py: bad tar\n")


if __name__ == "__main__":
    unittest.main()
