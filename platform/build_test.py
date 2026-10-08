import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class PlatformBuildTest(unittest.TestCase):
    def test_build_and_reject_invalid_policy_inputs(self):
        source = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("build.sh", "validate.py", "machines.json", "policies.json"):
                shutil.copyfile(source / name, root / name)
            subprocess.run(["bash", str(root / "build.sh")], check=True, capture_output=True)
            artifact = json.loads((root / "platform-endorsements.json").read_text())
            self.assertEqual(artifact["format"], "https://tinfoil.sh/predicate/platform-endorsements/v2")
            self.assertEqual(artifact["measurements"], {})
            self.assertEqual(artifact["machines"], json.loads((source / "machines.json").read_text()))
            self.assertEqual(artifact["policies"], json.loads((source / "policies.json").read_text()))

            originals = {name: (root / name).read_text() for name in ("machines.json", "policies.json")}
            mutations = {
                "unknown machine policy": ("machines.json", '{"abcd":"missing-policy"}'),
                "duplicate identifier": ("machines.json", '{"abcd":"a","abcd":"b"}'),
                "empty inventory": ("machines.json", '{}'),
            }
            for field, value in (("host_data", "0" * 64), ("minimum_tcb", {"bl_spl": -1}), ("minimum_abi_version", "bad")):
                changed = json.loads(originals["policies.json"])
                changed["amd-genoa-prod"]["sev_snp"][field] = value
                mutations[field] = ("policies.json", json.dumps(changed))
            changed = json.loads(originals["policies.json"])
            changed["tdx-h200-prod"]["tdx"]["platform_measurements"] = ["shape"]
            mutations["runtime measurement in policy"] = ("policies.json", json.dumps(changed))
            for label, (name, content) in mutations.items():
                with self.subTest(label=label):
                    for original, text in originals.items():
                        (root / original).write_text(text)
                    (root / name).write_text(content)
                    result = subprocess.run(["bash", str(root / "build.sh")], capture_output=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
