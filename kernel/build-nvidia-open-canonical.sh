#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 KERNEL_SOURCE NVIDIA_SOURCE KERNEL_RELEASE JOBS" >&2
    exit 2
fi

kernel_source=$1
nvidia_source=$2
kernel_release=$3
jobs=$4
build_uid=${TINFOIL_BUILD_UID:?}
build_gid=${TINFOIL_BUILD_GID:?}

mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /mnt
mkdir -p /mnt/tinfoil-linux-source /mnt/tinfoil-nvidia-open
mount --bind "$kernel_source" /mnt/tinfoil-linux-source
mount --bind "$nvidia_source" /mnt/tinfoil-nvidia-open

cd /mnt/tinfoil-nvidia-open
exec setpriv --reuid "$build_uid" --regid "$build_gid" --clear-groups \
    make -j "$jobs" \
    KERNEL_UNAME="$kernel_release" \
    IGNORE_CC_MISMATCH=1 \
    SYSSRC=/mnt/tinfoil-linux-source \
    LD=/usr/bin/ld.bfd \
    CONFIG_X86_KERNEL_IBT= \
    IGNORE_PREEMPT_RT_PRESENCE=1 \
    IGNORE_XEN_PRESENCE=1 \
    NV_EXCLUDE_KERNEL_MODULES="nvidia-drm nvidia-peermem" \
    modules
