#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 7 ]; then
    echo "usage: $0 KERNEL_SOURCE NVIDIA_SOURCE OUTPUT KERNEL_RELEASE BUILD_UID BUILD_GID MODULE_LIST" >&2
    exit 2
fi

kernel_source=$1
nvidia_source=$2
output=$3
kernel_release=$4
build_uid=$5
build_gid=$6
module_list=$7

if [[ ! "$build_uid" =~ ^[0-9]+$ || ! "$build_gid" =~ ^[0-9]+$ ]]; then
    echo "build uid and gid must be numeric" >&2
    exit 2
fi

export KBUILD_BUILD_TIMESTAMP='Thu Jan  1 00:00:00 UTC 1970'
export KBUILD_BUILD_USER=tinfoil
export KBUILD_BUILD_HOST=tinfoil-builder
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset MAKEFLAGS MFLAGS ARCH CROSS_COMPILE CC CFLAGS CPPFLAGS KCFLAGS KCPPFLAGS LDFLAGS

mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /mnt
mkdir -p /mnt/source/kernel /mnt/source/nvidia /mnt/output /mnt/work
touch /mnt/source/modules
mount --bind "$kernel_source" /mnt/source/kernel
mount --bind "$nvidia_source" /mnt/source/nvidia
mount --bind "$module_list" /mnt/source/modules
mount --bind "$output" /mnt/output
chown "$build_uid:$build_gid" /mnt/work /mnt/output

exec setpriv --reuid "$build_uid" --regid "$build_gid" --clear-groups \
    /bin/bash -Eeuo pipefail -c '
        cp -a /mnt/source/kernel /mnt/work/kernel
        cp -a /mnt/source/nvidia /mnt/work/nvidia
        chmod -R u+w /mnt/work/kernel /mnt/work/nvidia
        install -m 0644 /mnt/work/kernel/vmlinux.symvers /mnt/work/kernel/Module.symvers
        make -C /mnt/work/kernel KERNELVERSION=7.0.0 modules_prepare
        make -C /mnt/work/nvidia -j 1 \
            KERNEL_UNAME="$1" \
            IGNORE_CC_MISMATCH=1 \
            SYSSRC=/mnt/work/kernel \
            LD=/usr/bin/ld.bfd \
            CONFIG_X86_KERNEL_IBT= \
            IGNORE_PREEMPT_RT_PRESENCE=1 \
            IGNORE_XEN_PRESENCE=1 \
            NV_EXCLUDE_KERNEL_MODULES="nvidia-drm nvidia-peermem" \
            modules
        while IFS= read -r module; do
            install -m 0644 "/mnt/work/nvidia/$module" "/mnt/output/$module"
        done < /mnt/source/modules
    ' build "$kernel_release"
