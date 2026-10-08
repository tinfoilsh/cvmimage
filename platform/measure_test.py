#!/usr/bin/env python3

import unittest

import measure


class QemuShapeTest(unittest.TestCase):
    def test_v011_fixed_virtio_topology(self):
        shape = measure.qemu_shape(
            "65536M",
            {
                "cpus": 16,
                "disks": 4,
                "memory": "65536M",
                "pci_hole64_size": "4096G",
                "profile": "single",
                "qemu_source": "qemu:10.1.0",
            },
        )

        self.assertEqual(
            shape["devices"][:6],
            [
                "virtio-serial-pci,bus=pcie.0,addr=0x1,disable-legacy=on,iommu_platform=true,romfile=",
                "virtio-net-pci,netdev=net0,bus=pcie.0,addr=0x2,disable-legacy=on,iommu_platform=true,romfile=",
                "virtio-blk-pci,drive=disk0,id=blk0,bus=pcie.0,addr=0x4,disable-legacy=on,iommu_platform=true,romfile=",
                "virtio-blk-pci,drive=disk1,id=blk1,bus=pcie.0,addr=0x5,disable-legacy=on,iommu_platform=true,romfile=",
                "virtio-blk-pci,drive=disk2,id=blk2,bus=pcie.0,addr=0x6,disable-legacy=on,iommu_platform=true,romfile=",
                "virtio-blk-pci,drive=disk3,id=blk3,bus=pcie.0,addr=0x7,disable-legacy=on,iommu_platform=true,romfile=",
            ],
        )
        self.assertEqual(
            shape["drives"],
            [
                "file=/dev/null,if=none,id=disk0,format=raw,readonly=on",
                "file=/dev/null,if=none,id=disk1,format=raw,readonly=on",
                "file=/dev/null,if=none,id=disk2,format=raw,readonly=on",
                "file=/dev/null,if=none,id=disk3,format=raw,readonly=on",
            ],
        )
        self.assertIn(
            "pcie-root-port,id=pci.1,bus=pcie.0,slot=1,pref64-reserve=512G",
            shape["devices"],
        )
        self.assertEqual(
            shape["fw_cfg"],
            ["name=opt/ovmf/X-PciMmio64Mb,string=262144"],
        )


if __name__ == "__main__":
    unittest.main()
