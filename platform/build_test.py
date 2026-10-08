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
            (root / "machines.json").write_text("{}")
            invalid = subprocess.run(["bash", str(root / "build.sh")], capture_output=True)
            self.assertNotEqual(invalid.returncode, 0)

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


    def test_rejects_invalid_inventory_and_policy_inputs(self):
        source = Path(__file__).resolve().parent
        policies = json.loads((source / "policies.json").read_text())
        machines = json.loads((source / "machines.json").read_text())
        identifier, policy = next(iter(machines.items()))
        duplicate = json.dumps(identifier) + ":" + json.dumps(policy)
        mutations = [("machines.json", "{" + duplicate + "," + duplicate + "}", "duplicate JSON keys")]
        for field, value in (
            ("minimum_api_version", 1.5),
            ("minimum_abi_version", 1.5),
            ("minimum_api_version", "1.5\n"),
            ("minimum_abi_version", "１.５"),
            ("host_data", "0" * 63 + "\n"),
            ("image_id", "0" * 31 + "\n"),
            ("minimum_tcb", {"bl_spl": -1, "tee_spl": 0, "snp_spl": 0, "ucode_spl": 0}),
        ):
            changed = copy.deepcopy(policies)
            changed["amd-genoa-prod"]["sev_snp"][field] = value
            mutations.append(("policies.json", json.dumps(changed), field))
        for platform, block in (("amd-genoa-prod", "sev_snp"), ("tdx-h200-prod", "tdx")):
            changed = copy.deepcopy(policies)
            changed[platform][block] = []
            mutations.append(("policies.json", json.dumps(changed), "must be an object"))
        changed = copy.deepcopy(policies)
        changed["tdx-h200-prod"]["tdx"]["platform_measurements"] = [{}]
        mutations.append(("policies.json", json.dumps(changed), "platform_measurements"))
        platforms = json.loads((source / "platform.json").read_text())
        platforms[next(iter(platforms))]["profile"] = []
        mutations.append(("platform.json", json.dumps(platforms), "profile"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("build.sh", "validate.py", "machines.json", "policies.json", "platform.json"):
                shutil.copyfile(source / name, root / name)
            shutil.copytree(source / "platforms", root / "platforms")
            (root / "hardware-measurements.json").write_text("{}")
            originals = {name: (root / name).read_text() for name in ("machines.json", "policies.json", "platform.json")}
            for name, content, error in mutations:
                with self.subTest(file=name, error=error):
                    for original, text in originals.items():
                        (root / original).write_text(text)
                    (root / name).write_text(content)
                    result = subprocess.run(["bash", str(root / "build.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertFalse((root / "platform-endorsements-classic.json").exists())
                    self.assertFalse((root / "platform-endorsements.json").exists())


if __name__ == "__main__":
    unittest.main()
