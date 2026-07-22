import errno
import hashlib
import multiprocessing
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import rootfs_artifacts, runtime_artifact_bridge as bridge


def prepare_worker(root: str, queue) -> None:
    bridge.REPO = Path(root)
    try:
        bridge.prepare()
        queue.put(None)
    except Exception as error:
        queue.put(str(error))


class RuntimeArtifactBridgeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.entries = self.create_sources()
        (self.root / "build").chmod(0o700)
        self.patch = mock.patch.object(bridge, "REPO", self.root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def create_sources(self):
        entries = {}
        manifests = {producer: [] for producer in rootfs_artifacts.PRODUCERS}
        for name, expected in rootfs_artifacts.EXPECTED.items():
            producer, kind, source_path, mode, link_target, destination, source_kind = expected
            if kind == "file":
                content = f"fixed runtime artifact: {name}\n".encode()
                source = self.root / bridge.PRODUCER_ROOTS[producer] / source_path
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(content)
                source.chmod(int(mode, 8))
                digest = hashlib.sha256(content).hexdigest()
            else:
                digest = "-"
            entry = rootfs_artifacts.Entry(
                producer,
                name,
                kind,
                source_path,
                mode,
                "0",
                "0",
                digest,
                link_target,
                destination,
                source_kind,
                f"{producer}:fixed-revision",
                "fixed-build-parameters",
            )
            entries[name] = entry
            manifests[producer].append(entry)
        lock = self.root / bridge.LOCK
        lock.parent.mkdir(parents=True)
        lock.write_text(self.serialize(entries.values()))
        for producer, producer_entries in manifests.items():
            manifest = self.root / bridge.PRODUCER_ROOTS[producer] / "rootfs-artifacts.tsv"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(self.serialize(producer_entries))
            manifest.chmod(0o644)
        return entries

    @staticmethod
    def serialize(entries):
        return "".join("\t".join(entry.__dict__.values()) + "\n" for entry in entries)

    def generated(self):
        return self.root / bridge.OUTPUT

    def contract_files(self):
        lock_content = (self.root / bridge.LOCK).read_bytes()
        marker = f"{bridge.SCHEMA}\t{hashlib.sha256(lock_content).hexdigest()}\n".encode()
        manifests = {
            producer: (self.root / relative / "rootfs-artifacts.tsv").read_bytes()
            for producer, relative in bridge.PRODUCER_ROOTS.items()
        }
        return bridge.expected_files(self.entries, manifests, marker)

    def staging(self):
        state = self.root / "build" / bridge.STATE
        return sorted(state.glob(".runtime-artifacts.*")) if state.exists() else []


    def tree_digest(self, root):
        digest = hashlib.sha256()
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix().encode()
            metadata = path.lstat()
            digest.update(relative + b"\0" + f"{metadata.st_mode:o}".encode() + b"\0")
            if path.is_file():
                digest.update(path.read_bytes())
        return digest.hexdigest()

    def test_prepare_exact_shape_and_atomic_replacement(self):
        bridge.prepare()
        expected = set(bridge.expected_shape(self.contract_files()))
        actual = {path.relative_to(self.generated()).as_posix() for path in self.generated().rglob("*")}
        self.assertEqual(actual, expected)
        self.assertEqual((self.generated() / "BUILD.bazel").read_bytes(), bridge.BUILD_CONTENT)
        first = self.tree_digest(self.generated())
        bridge.prepare()
        self.assertEqual(self.tree_digest(self.generated()), first)

    def test_unmarked_and_symlink_destinations_are_preserved(self):
        destination = self.generated()
        destination.mkdir(parents=True)
        victim = destination / "victim"
        victim.write_text("preserve")
        with self.assertRaises(ValueError):
            bridge.prepare()
        self.assertEqual(victim.read_text(), "preserve")
        shutil.rmtree(destination)
        target = self.root / "target"
        target.mkdir()
        destination.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            bridge.prepare()
        self.assertTrue(destination.is_symlink())

    def test_failure_keeps_previous_package(self):
        bridge.prepare()
        before = self.tree_digest(self.generated())
        source = self.root / bridge.PRODUCER_ROOTS["go"] / self.entries["tinfoil-init"].source_path
        source.write_bytes(b"mutated")
        source.chmod(0o755)
        with self.assertRaises(ValueError):
            bridge.prepare()
        self.assertEqual(self.tree_digest(self.generated()), before)

    def test_invalid_temporary_package_is_never_installed(self):
        original = bridge.validate_tree

        def reject_temporary(parent, name, files):
            if name.startswith(".runtime-artifacts."):
                raise ValueError("injected pre-publication failure")
            return original(parent, name, files)

        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    bridge.prepare()
                    before = self.tree_digest(self.generated())
                with mock.patch.object(bridge, "validate_tree", side_effect=reject_temporary):
                    with self.assertRaisesRegex(ValueError, "pre-publication"):
                        bridge.prepare()
                if existing:
                    self.assertEqual(self.tree_digest(self.generated()), before)
                    shutil.rmtree(self.generated())
                else:
                    self.assertFalse(self.generated().exists())
                self.assertEqual(self.staging(), [])

    def test_initial_publication_preserves_raced_destination(self):
        real_publish = bridge.publish

        def race_destination(source_parent, temporary, destination_parent, destination):
            os.mkdir(destination, 0o755, dir_fd=destination_parent)
            raced = os.open(f"{destination}/victim", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=destination_parent)
            os.write(raced, b"preserve")
            os.close(raced)
            real_publish(source_parent, temporary, destination_parent, destination)

        with mock.patch.object(bridge, "publish", side_effect=race_destination):
            with self.assertRaisesRegex(ValueError, "File exists"):
                bridge.prepare()
        self.assertEqual((self.generated() / "victim").read_bytes(), b"preserve")
        self.assertEqual(self.staging(), [])

    def test_concurrent_preparation_serializes(self):
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        processes = [context.Process(target=prepare_worker, args=(str(self.root), queue)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual([queue.get(timeout=2) for _ in processes], [None, None])
        build = os.open(self.root / "build", os.O_RDONLY | os.O_DIRECTORY)
        try:
            bridge.validate_tree(build, "runtime-artifacts", self.contract_files())
        finally:
            os.close(build)

    def test_existing_tree_bytes_are_authenticated_before_replacement(self):
        bridge.prepare()
        paths = ["BUILD.bazel", bridge.MARKER]
        paths.extend(f"producers/{producer}/rootfs-artifacts.tsv" for producer in sorted(bridge.PRODUCER_ROOTS))
        paths.extend(
            f"producers/{entry.producer}/{entry.source_path}"
            for entry in self.entries.values()
            if entry.kind == "file"
        )
        for relative in paths:
            with self.subTest(relative=relative):
                target = self.generated() / relative
                original = target.read_bytes()
                target.write_bytes(original + b"mutation")
                before = self.tree_digest(self.generated())
                with self.assertRaisesRegex(ValueError, "content mismatch"):
                    bridge.prepare()
                self.assertEqual(self.tree_digest(self.generated()), before)
                self.assertEqual(self.staging(), [])
                shutil.rmtree(self.generated())
                bridge.prepare()

    def test_failed_writes_and_fsyncs_remove_owned_staging(self):
        original_write = os.write
        write_calls = 0

        def fail_write(fd, content):
            nonlocal write_calls
            write_calls += 1
            if write_calls == 2:
                raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
            return original_write(fd, content)

        with mock.patch.object(bridge.os, "write", side_effect=fail_write):
            with self.assertRaises(OSError):
                bridge.prepare()
        self.assertEqual(self.staging(), [])

        original_fsync = os.fsync
        fsync_calls = 0

        def fail_fsync(fd):
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise OSError(errno.EIO, os.strerror(errno.EIO))
            return original_fsync(fd)

        with mock.patch.object(bridge.os, "fsync", side_effect=fail_fsync):
            with self.assertRaises(OSError):
                bridge.prepare()
        self.assertEqual(self.staging(), [])

    def test_rename_failures_remove_owned_staging(self):
        with mock.patch.object(bridge, "publish", side_effect=ValueError("renameat2 publication failed: injected")):
            with self.assertRaisesRegex(ValueError, "renameat2"):
                bridge.prepare()
        self.assertEqual(self.staging(), [])
        bridge.prepare()
        before = self.tree_digest(self.generated())
        with mock.patch.object(bridge, "exchange", side_effect=ValueError("renameat2 exchange failed: injected")):
            with self.assertRaisesRegex(ValueError, "renameat2"):
                bridge.prepare()
        self.assertEqual(self.tree_digest(self.generated()), before)
        self.assertEqual(self.staging(), [])

    def test_marker_transition_failure_removes_owned_staging(self):
        original = bridge.write_file

        def fail_final_marker(parent, name, content, mode):
            if name == bridge.MARKER:
                raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
            return original(parent, name, content, mode)

        with mock.patch.object(bridge, "write_file", side_effect=fail_final_marker):
            with self.assertRaises(OSError):
                bridge.prepare()
        self.assertEqual(self.staging(), [])

    def test_cleanup_preserves_hostile_staging(self):
        original = bridge.snapshot_file
        injected = False

        def inject_hostile(*args, **kwargs):
            nonlocal injected
            if not injected:
                injected = True
                stage = self.staging()[0]
                self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
                (stage / "hostile").symlink_to("/tmp")
                raise ValueError("injected staging failure")
            return original(*args, **kwargs)

        with mock.patch.object(bridge, "snapshot_file", side_effect=inject_hostile):
            with self.assertRaisesRegex(ValueError, "injected staging"):
                bridge.prepare()
        stages = self.staging()
        self.assertEqual(len(stages), 1)
        self.assertTrue((stages[0] / "hostile").is_symlink())
        self.assertFalse(self.generated().exists())

    def assert_cleanup_preserves_replacement(self, directory):
        real_stat = bridge.os.stat
        calls = 0

        def replace_before_recheck(path, *args, **kwargs):
            nonlocal calls
            if path == "replace-me":
                calls += 1
                if calls == 2:
                    if directory:
                        os.rmdir(path, dir_fd=kwargs["dir_fd"])
                        os.mkdir(path, 0o700, dir_fd=kwargs["dir_fd"])
                        replacement_path = f"{path}/victim"
                    else:
                        os.unlink(path, dir_fd=kwargs["dir_fd"])
                        replacement_path = path
                    replacement = os.open(replacement_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=kwargs["dir_fd"])
                    os.write(replacement, b"replacement")
                    os.close(replacement)
            return real_stat(path, *args, **kwargs)

        kind = "directory" if directory else "file"
        stage = self.root / "build" / bridge.STATE / f".runtime-artifacts.{kind}-race"
        stage.mkdir(parents=True, mode=0o700)
        (stage / bridge.PREPARING).write_bytes(b"owned")
        (stage / bridge.PREPARING).chmod(0o600)
        target = stage / "replace-me"
        target.mkdir() if directory else target.write_bytes(b"original")
        parent = os.open(stage.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(bridge.os, "stat", side_effect=replace_before_recheck):
                bridge.remove_staging(parent, stage.name, b"owned", {})
        finally:
            os.close(parent)
        replacement = target / "victim" if directory else target
        self.assertEqual(replacement.read_bytes(), b"replacement")

    def test_cleanup_preserves_replaced_staging_file(self):
        self.assert_cleanup_preserves_replacement(False)

    def test_cleanup_preserves_replaced_staging_directory(self):
        self.assert_cleanup_preserves_replacement(True)

    def test_prior_tree_is_reauthenticated_immediately_before_deletion(self):
        bridge.prepare()
        before = self.tree_digest(self.generated())
        real_remove = bridge.remove_owned

        def mutate_before_remove(parent, name, files):
            stage = Path(f"/proc/self/fd/{parent}") / name
            build_file = stage / "BUILD.bazel"
            build_file.write_bytes(build_file.read_bytes() + b"mutation")
            return real_remove(parent, name, files)

        with mock.patch.object(bridge, "remove_owned", side_effect=mutate_before_remove):
            with self.assertRaisesRegex(ValueError, "content mismatch"):
                bridge.prepare()
        self.assertEqual(self.tree_digest(self.generated()), before)
        stages = self.staging()
        self.assertEqual(len(stages), 1)
        self.assertTrue((stages[0] / "BUILD.bazel").read_bytes().endswith(b"mutation"))

    def test_destination_replacement_race_is_detected_and_preserved(self):
        bridge.prepare()
        real_exchange = bridge.exchange

        def replace_destination(source_parent, temporary, destination_parent, destination):
            os.rename(destination, "runtime-artifacts.saved", src_dir_fd=destination_parent, dst_dir_fd=destination_parent)
            os.mkdir(destination, 0o755, dir_fd=destination_parent)
            hostile_parent = os.open(destination, os.O_RDONLY | os.O_DIRECTORY, dir_fd=destination_parent)
            try:
                hostile = os.open("victim", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=hostile_parent)
                os.close(hostile)
            finally:
                os.close(hostile_parent)
            real_exchange(source_parent, temporary, destination_parent, destination)

        with mock.patch.object(bridge, "exchange", side_effect=replace_destination):
            with self.assertRaises(ValueError):
                bridge.prepare()
        build = os.open(self.root / "build", os.O_RDONLY | os.O_DIRECTORY)
        try:
            bridge.validate_tree(build, "runtime-artifacts", self.contract_files())
        finally:
            os.close(build)
        self.assertEqual(len(self.staging()), 1)

    def test_private_state_and_untrusted_shared_build_policy(self):
        bridge.prepare()
        self.assertEqual(stat.S_IMODE((self.root / "build" / bridge.STATE).stat().st_mode), 0o700)
        (self.root / "build").chmod(0o775)
        with self.assertRaisesRegex(ValueError, "group trust"):
            bridge.prepare()

    def test_existing_wrong_mode_package_is_preserved(self):
        bridge.prepare()
        marker = self.generated() / bridge.MARKER
        marker.chmod(0o600)
        with self.assertRaises(ValueError):
            bridge.prepare()
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
