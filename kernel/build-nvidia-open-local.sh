#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"

nvidia_version="${TINFOIL_NVIDIA_OPEN_VERSION:-595.71.05}"
nvidia_package_version="${TINFOIL_NVIDIA_OPEN_PACKAGE_VERSION:-595.71.05-1ubuntu1}"
nvidia_repo_url="${TINFOIL_NVIDIA_OPEN_REPO_URL:-https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64}"
kernel_source_version="${TINFOIL_KERNEL_SOURCE_VERSION:-7.0.0}"
kernel_version_override="${TINFOIL_KERNEL_VERSION_OVERRIDE:-$kernel_source_version}"
kernel_out_dir="${TINFOIL_KERNEL_OUT_DIR:-$kernel_dir/out}"
kernel_release="${TINFOIL_KERNEL_RELEASE:-$(tr -d '\n' < "$kernel_out_dir/kernel.release")}"
kernel_source_dir="${TINFOIL_KERNEL_SOURCE_DIR:-$kernel_dir/build/linux-source-$kernel_source_version}"
scratch_dir="${TINFOIL_NVIDIA_OPEN_BUILD_DIR:-$kernel_dir/build/nvidia-open-$nvidia_version}"
# finit_module loads by file descriptor, so keep the three measured artifacts
# at a fixed application-owned path instead of parsing uname at runtime.
stage_dir="${TINFOIL_NVIDIA_OPEN_STAGE_DIR:-$repo_dir/image/rootfs-overlay/usr/lib/tinfoil/kernel-modules}"

source_deb="nvidia-kernel-source-open_${nvidia_package_version}_amd64.deb"
dkms_deb="nvidia-dkms-open_${nvidia_package_version}_amd64.deb"
source_sha256="823e5d99d43eb51a10b9ef548469a1fa27a87821a18d43799e4086f91ecbc5ca"
dkms_sha256="63931656d1ee42b0522f6180ef292c2d942eeb9f8ce7940882486273a319a994"

required_modules=(
    nvidia.ko
    nvidia-uvm.ko
    nvidia-modeset.ko
)
make_version_args=(KERNELVERSION="$kernel_version_override")

export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-$(date -u -d @0)}"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-tinfoil}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-tinfoil-builder}"

download_deb() {
    local name="$1"
    local sha="$2"
    local dest="$scratch_dir/debs/$name"

    mkdir -p "$scratch_dir/debs"
    if [ ! -f "$dest" ]; then
        if [ "${TINFOIL_OFFLINE:-0}" = 1 ]; then
            echo "missing pinned offline NVIDIA package: $dest" >&2
            exit 1
        fi
        curl -fL --retry 3 --retry-delay 2 "$nvidia_repo_url/$name" -o "$dest"
    fi
    printf '%s  %s\n' "$sha" "$dest" | sha256sum -c -
}

require_file() {
    local path="$1"
    local label="$2"
    if [ ! -s "$path" ]; then
        echo "missing $label: $path" >&2
        exit 1
    fi
}

require_file "$kernel_out_dir/kernel.release" "custom kernel release"
require_file "$kernel_source_dir/.config" "custom kernel config"
require_file "$kernel_source_dir/arch/x86/boot/bzImage" "custom kernel image"
require_file "$kernel_source_dir/vmlinux.symvers" "custom kernel symbol versions"

actual_release="$(make -s -C "$kernel_source_dir" "${make_version_args[@]}" kernelrelease)"
if [ "$actual_release" != "$kernel_release" ]; then
    cat >&2 <<EOF
kernel release mismatch
  kernel/out: $kernel_release
  source:     $actual_release
EOF
    exit 1
fi

download_deb "$source_deb" "$source_sha256"
download_deb "$dkms_deb" "$dkms_sha256"

rm -rf "$scratch_dir/extract"
mkdir -p "$scratch_dir/extract/source" "$scratch_dir/extract/dkms"
dpkg-deb -x "$scratch_dir/debs/$source_deb" "$scratch_dir/extract/source"
dpkg-deb -x "$scratch_dir/debs/$dkms_deb" "$scratch_dir/extract/dkms"

nvidia_source_dir="$scratch_dir/extract/source/usr/src/nvidia-$nvidia_version"
patch_file="$scratch_dir/extract/dkms/usr/src/nvidia-$nvidia_version/patches/disable_fstack-clash-protection_fcf-protection.patch"
require_file "$nvidia_source_dir/Makefile" "NVIDIA open module Makefile"
require_file "$patch_file" "NVIDIA DKMS compiler flag patch"

patch --forward --batch -p1 -d "$nvidia_source_dir" < "$patch_file"
printf '%s\n' '#!/bin/sh' 'exec /usr/bin/pahole "$@"' > "$nvidia_source_dir/pahole.sh"
chmod 0755 "$nvidia_source_dir/pahole.sh"

install -m 0644 "$kernel_source_dir/vmlinux.symvers" "$kernel_source_dir/Module.symvers"
make -C "$kernel_source_dir" "${make_version_args[@]}" modules_prepare > "$scratch_dir/modules-prepare.log" 2>&1

build_log="$scratch_dir/build.log"
if ! sudo env \
        TINFOIL_BUILD_UID="$(id -u)" \
        TINFOIL_BUILD_GID="$(id -g)" \
        unshare --mount --propagation private \
        "$kernel_dir/build-nvidia-open-canonical.sh" \
        "$kernel_source_dir" "$nvidia_source_dir" "$kernel_release" \
        "${TINFOIL_NVIDIA_OPEN_JOBS:-$(nproc)}" > "$build_log" 2>&1; then
    tail -n 200 "$build_log" >&2
    exit 1
fi

for module in "${required_modules[@]}"; do
    require_file "$nvidia_source_dir/$module" "built NVIDIA module"
    case "$(modinfo -F vermagic "$nvidia_source_dir/$module")" in
        "$kernel_release "*) ;;
        *)
            echo "module $module has unexpected vermagic: $(modinfo -F vermagic "$nvidia_source_dir/$module")" >&2
            exit 1
            ;;
    esac
done

module_versions="$(modprobe --dump-modversions "$nvidia_source_dir/nvidia.ko")"
for symbol in pci_iounmap iterate_fd init_pid_ns pci_restore_state; do
    expected="$(awk -v symbol="$symbol" '$2 == symbol { print $1; exit }' "$kernel_source_dir/Module.symvers")"
    actual="$(awk -v symbol="$symbol" '$2 == symbol { print $1; exit }' <<<"$module_versions")"
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
        echo "module CRC mismatch for $symbol: expected ${expected:-<missing>} got ${actual:-<missing>}" >&2
        exit 1
    fi
done

install -d -m 0755 "$stage_dir"
rm -f "$stage_dir"/nvidia*.ko "$stage_dir"/nvidia*.ko.zst
for module in "${required_modules[@]}"; do
    install -m 0644 "$nvidia_source_dir/$module" "$stage_dir/$module"
done

out_dir="$kernel_out_dir/nvidia-open"
rm -rf "$out_dir"
install -d -m 0755 "$out_dir"
sha256sum "$stage_dir"/nvidia*.ko > "$out_dir/checksums.sha256"
for module in "${required_modules[@]}"; do
    printf '%s %s\n' "$module" "$(modinfo -F vermagic "$stage_dir/$module")"
done > "$out_dir/vermagic.txt"
modprobe --dump-modversions "$stage_dir/nvidia.ko" > "$out_dir/nvidia.modversions"

cat <<EOF
custom NVIDIA open modules staged
  release:  $kernel_release
  source:   $nvidia_package_version
  stage:    $stage_dir
  checksums:$out_dir/checksums.sha256
EOF
