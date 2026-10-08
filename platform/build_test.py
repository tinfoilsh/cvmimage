import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class PlatformBuildTest(unittest.TestCase):
    def test_preserves_classic_policies_and_derives_runtime_policies(self):
        source = Path(__file__).resolve().parent
        measurements = {"test-shape": {"mrtd": "a" * 96}}
        policies = json.loads((source / "policies.json").read_text())
        # A stricter policy must not be lowered by the runtime ABI floor.
        policies["amd-genoa-prod"]["sev_snp"]["minimum_abi_version"] = "2.0"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("build.sh", "validate.py", "machines.json", "platform.json"):
                shutil.copyfile(source / name, root / name)
            shutil.copytree(source / "platforms", root / "platforms")
            (root / "policies.json").write_text(json.dumps(policies))
            (root / "hardware-measurements.json").write_text(json.dumps(measurements))
            subprocess.run(["bash", str(root / "build.sh")], check=True, capture_output=True)
            classic = json.loads((root / "platform-endorsements-classic.json").read_text())
            runtime = json.loads((root / "platform-endorsements.json").read_text())

        self.assertEqual(classic, {
            "format": "https://tinfoil.sh/predicate/platform-endorsements/v1",
            "measurements": measurements,
            "machines": json.loads((source / "machines.json").read_text()),
            "policies": policies,
        })
        expected = copy.deepcopy(classic)
        expected["format"] = "https://tinfoil.sh/predicate/platform-endorsements/v2"
        expected["measurements"] = {}
        for policy in expected["policies"].values():
            if policy["platform"] == "sev-snp":
                block = policy["sev_snp"]
                del block["host_data"]
                block["minimum_abi_version"] = max(block["minimum_abi_version"], "1.51", key=lambda v: tuple(map(int, v.split("."))))
            else:
                del policy["tdx"]["platform_measurements"]
        self.assertEqual(runtime, expected)


if __name__ == "__main__":
    unittest.main()
