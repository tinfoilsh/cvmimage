#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"
source "$kernel_dir/profile.sh"
select_tinfoil_kernel_profile
if [ "$kernel_profile" != release ]; then
    echo "NVIDIA modules are not defined for kernel profile: $kernel_profile" >&2
    exit 2
fi
kernel_build_dir="$kernel_build_root"
kernel_source_dir="$kernel_build_dir/linux-source-7.0.0"
kernel_release_file="$kernel_out_dir/kernel.release"
kernel_profile_file="$kernel_out_dir/profile"
output_dir="${TINFOIL_NVIDIA_OUTPUT_DIR:-$kernel_out_dir/rootfs-artifacts/nvidia-modules}"
package_cache_dir="${TINFOIL_NVIDIA_PACKAGE_CACHE:-$kernel_dir/build/nvidia-packages}"
host_uid="${HOST_UID:-$(id -u)}"
host_gid="${HOST_GID:-$(id -g)}"

if [[ ! "$host_uid" =~ ^[0-9]+$ || ! "$host_gid" =~ ^[0-9]+$ ]]; then
    echo "HOST_UID and HOST_GID must be numeric" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ] &&
    { [ "$host_uid" != "$(id -u)" ] || [ "$host_gid" != "$(id -g)" ]; }; then
    echo "non-root NVIDIA builds must use the current uid and gid" >&2
    exit 2
fi

readonly nvidia_version=595.71.05
readonly nvidia_package_version=595.71.05-1ubuntu1
readonly nvidia_repo_url=https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64
readonly source_deb="nvidia-kernel-source-open_${nvidia_package_version}_amd64.deb"
readonly dkms_deb="nvidia-dkms-open_${nvidia_package_version}_amd64.deb"
readonly source_sha256=823e5d99d43eb51a10b9ef548469a1fa27a87821a18d43799e4086f91ecbc5ca
readonly dkms_sha256=63931656d1ee42b0522f6180ef292c2d942eeb9f8ce7940882486273a319a994
mapfile -t required_modules < "$kernel_dir/nvidia-modules.txt"
readonly -a required_modules

export KBUILD_BUILD_TIMESTAMP='Thu Jan  1 00:00:00 UTC 1970'
export KBUILD_BUILD_USER=tinfoil
export KBUILD_BUILD_HOST=tinfoil-builder
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset MAKEFLAGS MFLAGS ARCH CROSS_COMPILE CC CFLAGS CPPFLAGS KCFLAGS KCPPFLAGS LDFLAGS

check_toolchain() {
    if [ "$(dpkg-query -W -f='${Version}' gcc)" != '4:15.2.0-5ubuntu1' ] ||
        [ "$(dpkg-query -W -f='${Version}' binutils)" != '2.46-3ubuntu2' ] ||
        [ "$(dpkg-query -W -f='${Version}' dwarves)" != '1.31-2ubuntu1' ] ||
        [ "$(dpkg-query -W -f='${Version}' kmod)" != '34.2-2ubuntu2' ]; then
        echo "non-canonical NVIDIA module toolchain" >&2
        exit 1
    fi
}

require_file() {
    local path=$1
    local label=$2
    if [ ! -s "$path" ]; then
        echo "missing $label: $path" >&2
        exit 1
    fi
}

download_deb() {
    local name=$1
    local sha256=$2
    local destination="$package_cache_dir/$name"
    local checksum_output

    mkdir -p "$package_cache_dir"
    if [ ! -f "$destination" ]; then
        if [ "${TINFOIL_OFFLINE:-0}" = 1 ]; then
            echo "missing pinned offline NVIDIA package: $destination" >&2
            exit 1
        fi
        curl -fL --retry 3 --retry-delay 2 "$nvidia_repo_url/$name" -o "$destination"
        if [ "$(id -u)" -eq 0 ]; then
            chown "$host_uid:$host_gid" "$destination"
        fi
    fi
    if ! checksum_output="$(printf '%s  %s\n' "$sha256" "$destination" | sha256sum -c --strict - 2>&1)"; then
        printf '%s\n' "$checksum_output" >&2
        echo "removing NVIDIA package with checksum mismatch: $destination" >&2
        rm -f -- "$destination"
        exit 1
    fi
    printf '%s\n' "$destination"
}

module_vermagic() {
    modinfo -F vermagic "$1"
}

module_versions() {
    modprobe --dump-modversions "$1"
}

validate_nvidia_modules() {
    local source_dir=$1
    local module_dir=$2
    local release=$3
    local module vermagic module_version_data symbol expected actual

    for module in "${required_modules[@]}"; do
        require_file "$module_dir/$module" "built NVIDIA module"
        vermagic="$(module_vermagic "$module_dir/$module")"
        case "$vermagic" in
            "$release "*) ;;
            *)
                echo "module $module has unexpected vermagic: $vermagic" >&2
                exit 1
                ;;
        esac
    done

    module_version_data="$(module_versions "$module_dir/nvidia.ko")"
    for symbol in pci_iounmap iterate_fd init_pid_ns pci_restore_state; do
        expected="$(awk -v symbol="$symbol" '$2 == symbol { print $1; exit }' "$source_dir/vmlinux.symvers")"
        actual="$(awk -v symbol="$symbol" '$2 == symbol { print $1; exit }' <<< "$module_version_data")"
        if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
            echo "module CRC mismatch for $symbol: expected ${expected:-<missing>} got ${actual:-<missing>}" >&2
            exit 1
        fi
    done
}

write_bazel_module_package() {
    local destination=$1
    local module temporary

    for module in "${required_modules[@]}"; do
        if [[ ! "$module" =~ ^[a-z0-9-]+\.ko$ ]]; then
            echo "invalid NVIDIA module contract entry: $module" >&2
            return 1
        fi
    done

    temporary="$(mktemp "$destination/.BUILD.bazel.XXXXXXXX")"

    if ! {
        printf '%s\n' 'package(default_visibility = ["//visibility:public"])' ''
        printf '%s\n' 'filegroup(' '    name = "modules",' '    srcs = ['
        for module in "${required_modules[@]}"; do
            printf '        "%s",\n' "$module"
        done
        printf '%s\n' '    ],' ')'
    } > "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 0644 "$temporary"
    touch -d @0 "$temporary"
    mv -f -- "$temporary" "$destination/BUILD.bazel"
}

main() {
    check_toolchain

    require_file "$kernel_release_file" "custom kernel release"
    require_file "$kernel_source_dir/.config" "custom kernel config"
    require_file "$kernel_source_dir/arch/x86/boot/bzImage" "custom kernel image"
    require_file "$kernel_source_dir/vmlinux.symvers" "custom kernel symbol versions"
    require_file "$kernel_source_dir/include/config/kernel.release" "custom kernel release metadata"
    require_tinfoil_kernel_artifact_profile "$kernel_profile_file" "$kernel_release_file"

kernel_release="$(tr -d '\n' < "$kernel_release_file")"
actual_release="$(tr -d '\n' < "$kernel_source_dir/include/config/kernel.release")"
if [ "$actual_release" != "$kernel_release" ]; then
    echo "kernel release mismatch: $kernel_release != $actual_release" >&2
    exit 1
fi

source_package="$(download_deb "$source_deb" "$source_sha256")"
dkms_package="$(download_deb "$dkms_deb" "$dkms_sha256")"

mkdir -p "$kernel_build_dir"
scratch="$(mktemp -d "$kernel_build_dir/.nvidia-open.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/source" "$scratch/dkms" "$scratch/built-modules"
dpkg-deb -x "$source_package" "$scratch/source"
dpkg-deb -x "$dkms_package" "$scratch/dkms"

nvidia_source_dir="$scratch/source/usr/src/nvidia-$nvidia_version"
patch_file="$scratch/dkms/usr/src/nvidia-$nvidia_version/patches/disable_fstack-clash-protection_fcf-protection.patch"
require_file "$nvidia_source_dir/Makefile" "NVIDIA open module Makefile"
require_file "$patch_file" "NVIDIA DKMS compiler flag patch"

patch --forward --batch -p1 -d "$nvidia_source_dir" < "$patch_file"
printf '%s\n' '#!/bin/sh' 'exec /usr/bin/pahole "$@"' > "$nvidia_source_dir/pahole.sh"
chmod 0755 "$nvidia_source_dir/pahole.sh"

    build_log="$scratch/build.log"
    unshare_command=(unshare)
    if [ "$(id -u)" -ne 0 ]; then
        if ! command -v sudo >/dev/null 2>&1; then
            echo "non-root NVIDIA builds require sudo for the mount namespace" >&2
            exit 1
        fi
        unshare_command=(sudo unshare)
    fi
    if ! "${unshare_command[@]}" --mount --propagation private \
        "$kernel_dir/build-nvidia-open-canonical.sh" \
        "$kernel_source_dir" "$nvidia_source_dir" "$scratch/built-modules" \
        "$kernel_release" "$host_uid" "$host_gid" \
        "$kernel_dir/nvidia-modules.txt" > "$build_log" 2>&1; then
        tail -n 200 "$build_log" >&2
        exit 1
    fi

    validate_nvidia_modules "$kernel_source_dir" "$scratch/built-modules" "$kernel_release"

    rm -rf "$output_dir"
    install -d -m 0755 "$output_dir"
    for module in "${required_modules[@]}"; do
        install -m 0644 "$scratch/built-modules/$module" "$output_dir/$module"
        touch -d @0 "$output_dir/$module"
    done
    write_bazel_module_package "$output_dir"
    if [ "$(id -u)" -eq 0 ]; then
        chown -R "$host_uid:$host_gid" "$output_dir"
    fi

    printf 'NVIDIA modules: %s (%s)\n' "$output_dir" "$kernel_release"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
