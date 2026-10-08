#!/usr/bin/env python3

import unittest

import validate


class PlatformValidationTest(unittest.TestCase):
    def setUp(self):
        validate.errors.clear()
        self.config = {
            "cpus": 16,
            "disks": 4,
            "memory": "65536M",
            "pci_hole64_size": "4096G",
            "profile": "single",
            "qemu_source": "qemu:10.1.0",
        }
        self.shape = {"cpus": 16, "disks": 4, "memory_mb": 65536}

    def test_matching_platform_and_shape(self):
        validate.validate_platform("medium_1d_new", self.config, self.shape)

        self.assertEqual(validate.errors, [])

    def test_rejects_unpinned_qemu_source(self):
        self.config["qemu_source"] = "ubuntu:25.04"

        validate.validate_platform("medium_1d_new", self.config, self.shape)

        self.assertTrue(any("qemu_source" in error for error in validate.errors))

    def test_rejects_shape_drift(self):
        self.shape["disks"] = 5

        validate.validate_platform("medium_1d_new", self.config, self.shape)

        self.assertTrue(any("does not match platform.json" in error for error in validate.errors))


if __name__ == "__main__":
    unittest.main()
