#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
local_builder="$repo_dir/kernel/build-nvidia-open-local.sh"
canonical_builder="$repo_dir/kernel/build-nvidia-open-canonical.sh"

grep -Fqx 'verify-rootfs-artifacts: runtime-go-artifacts nvattest nvidia-module-artifacts' "$repo_dir/Makefile"
grep -Fqx 'nvidia-module-artifacts: custom-kernel-artifacts' "$repo_dir/Makefile"
grep -Fq 'build_uid="$(id -u)"' "$local_builder"
grep -Fq 'build_gid="$(id -g)"' "$local_builder"
grep -Fq '"$build_uid" "$build_gid"' "$local_builder"
grep -Fq 'exec setpriv --reuid "$build_uid" --regid "$build_gid" --clear-groups' "$canonical_builder"
grep -Fq 'make -C /mnt/work/nvidia -j 1' "$canonical_builder"
grep -Fq 'mount -o remount,bind,ro /mnt/source/kernel' "$canonical_builder"
grep -Fq 'mount -o remount,bind,ro /mnt/source/nvidia' "$canonical_builder"
grep -Fq 'cp -a /mnt/source/kernel /mnt/work/kernel' "$canonical_builder"
grep -Fq 'cp -a /mnt/source/nvidia /mnt/work/nvidia' "$canonical_builder"
grep -Fq '"$kernel_build_dir" "$kernel_source_dir" "$kernel_out_dir"' "$local_builder"
grep -Fq 'unset MAKEFLAGS MFLAGS ARCH CROSS_COMPILE CC CFLAGS CPPFLAGS KCFLAGS KCPPFLAGS LDFLAGS' "$local_builder"
grep -Fq "export KBUILD_BUILD_TIMESTAMP='Thu Jan  1 00:00:00 UTC 1970'" "$canonical_builder"
grep -Fq 'export KBUILD_BUILD_USER=tinfoil' "$canonical_builder"
grep -Fq 'export KBUILD_BUILD_HOST=tinfoil-builder' "$canonical_builder"
grep -Fq "dpkg-query -W -f='\${Version}' gcc" "$local_builder"

if grep -Eq 'TINFOIL_(BUILD_UID|BUILD_GID|NVIDIA_OPEN_(VERSION|PACKAGE|URL|SHA))' "$local_builder" "$canonical_builder"; then
    echo "module producer exposes a caller-controlled build input" >&2
    exit 1
fi
if grep -Eq '^exec make|^[[:space:]]+exec make' "$canonical_builder"; then
    echo "module producer runs make directly as root" >&2
    exit 1
fi
if grep -Fq 'make -s -C "$kernel_source_dir"' "$local_builder"; then
    echo "module producer probes the shared kernel source with make" >&2
    exit 1
fi

echo "runtime artifact producer structure is fixed and least-privileged"
