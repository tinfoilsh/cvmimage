#!/bin/sh
set -eu
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
finish() {
    echo "VOLUME_FIXTURE_RESULT=$1"
    sync
    poweroff -f
}
trap 'finish 1' EXIT
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o size=64m,nosuid,nodev tmpfs /run
for module in virtio_pci virtio_blk dm_mod dm_integrity dm_crypt ext4 authenc xts; do
    if ! modprobe "$module"; then
        echo "SKIP: fixture kernel cannot load $module"
        finish 77
    fi
done
stage=
for arg in $(/bin/busybox cat /proc/cmdline); do
    case "$arg" in volume_stage=*) stage=${arg#volume_stage=} ;; esac
done
if [ "$stage" = initialize ]; then
    /hardening.test -test.run='^Test(ShimInheritedUnixListener|ServiceSocketDomains|ServiceDangerousSyscalls)$' -test.v -test.timeout=1m
fi
TINFOIL_VOLUME_VM_STAGE="$stage" /volume.test -test.run='^TestVolumeVM$' -test.v -test.timeout=4m
trap - EXIT
finish 0
