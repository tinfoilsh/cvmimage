#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"
kernel_build_dir="${TINFOIL_KERNEL_BUILD_ROOT:-$kernel_dir/build}"
kernel_out_dir="${TINFOIL_KERNEL_OUT_DIR:-$kernel_dir/out}"
kernel_source_dir="$kernel_build_dir/linux-source-7.0.0"
output_dir="${TINFOIL_NVIDIA_OUTPUT_DIR:-$kernel_out_dir/rootfs-artifacts/nvidia-modules}"
kernel_release_file="$kernel_out_dir/kernel.release"

readonly nvidia_version=595.71.05
readonly nvidia_package_version=595.71.05-1ubuntu1
readonly nvidia_repo_url=https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64
readonly source_deb="nvidia-kernel-source-open_${nvidia_package_version}_amd64.deb"
readonly dkms_deb="nvidia-dkms-open_${nvidia_package_version}_amd64.deb"
readonly source_sha256=823e5d99d43eb51a10b9ef548469a1fa27a87821a18d43799e4086f91ecbc5ca
readonly dkms_sha256=63931656d1ee42b0522f6180ef292c2d942eeb9f8ce7940882486273a319a994
readonly -a required_modules=(nvidia.ko nvidia-uvm.ko nvidia-modeset.ko)
readonly package_cache_dir="$kernel_build_dir/nvidia-packages"

export KBUILD_BUILD_TIMESTAMP='Thu Jan  1 00:00:00 UTC 1970'
export KBUILD_BUILD_USER=tinfoil
export KBUILD_BUILD_HOST=tinfoil-builder
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset MAKEFLAGS MFLAGS ARCH CROSS_COMPILE CC CFLAGS CPPFLAGS KCFLAGS KCPPFLAGS LDFLAGS

[ "$(dpkg-query -W -f='${Version}' gcc)" = '4:15.2.0-5ubuntu1' ] && \
[ "$(dpkg-query -W -f='${Version}' binutils)" = '2.46-3ubuntu2' ] && \
[ "$(dpkg-query -W -f='${Version}' dwarves)" = '1.31-2ubuntu1' ] && \
[ "$(dpkg-query -W -f='${Version}' kmod)" = '34.2-2ubuntu2' ] || {
    echo "non-canonical NVIDIA module toolchain" >&2
    exit 1
}

require_file() {
    [ -f "$1" ] && [ -s "$1" ] || { echo "missing $2: $1" >&2; exit 1; }
    [ ! -L "$1" ] || { echo "refusing symlinked $2: $1" >&2; exit 1; }
}

cleanup_owned() {
    local directory=$1 parent=$2 prefix=$3
    [ -n "$directory" ] || return 0
    [ ! -L "$directory" ] && [ ! -L "$directory/.tinfoil-owned" ] && \
        [ -f "$directory/.tinfoil-owned" ] || {
        echo "refusing to clean unowned path: $directory" >&2
        return 1
    }
    case "$(realpath -e "$directory")" in "$(realpath -e "$parent")"/"$prefix".*) ;; *)
        echo "refusing to clean unexpected path: $directory" >&2; return 1;;
    esac
    rm -rf --one-file-system -- "$directory"
}

require_canonical_directory() {
    local directory=$1 label=$2
    [ -d "$directory" ] && [ ! -L "$directory" ] || {
        echo "refusing missing or symlinked $label: $directory" >&2
        exit 1
    }
    [ "$(realpath -e -- "$directory")" = "$directory" ] || {
        echo "refusing non-canonical or symlink-interposed $label: $directory" >&2
        exit 1
    }
}

require_file "$kernel_release_file" "custom kernel release"
require_file "$kernel_source_dir/.config" "custom kernel config"
require_file "$kernel_source_dir/arch/x86/boot/bzImage" "custom kernel image"
require_file "$kernel_source_dir/vmlinux.symvers" "custom kernel symbol versions"
require_file "$kernel_source_dir/include/config/kernel.release" "custom kernel release metadata"
for fixed_directory in "$kernel_dir" "$kernel_build_dir" "$kernel_source_dir" "$kernel_out_dir"; do
    [ -d "$fixed_directory" ] && [ ! -L "$fixed_directory" ] || {
        echo "refusing missing or symlinked fixed directory: $fixed_directory" >&2
        exit 1
    }
done
case "${TINFOIL_OFFLINE:-0}" in
    0 | 1) ;;
    *) echo "TINFOIL_OFFLINE must be 0 or 1" >&2; exit 1 ;;
esac

if [ -L "$package_cache_dir" ]; then
    echo "refusing symlinked NVIDIA package cache: $package_cache_dir" >&2
    exit 1
fi
if [ ! -e "$package_cache_dir" ]; then
    mkdir -- "$package_cache_dir"
fi
require_canonical_directory "$package_cache_dir" "NVIDIA package cache"

kernel_release="$(tr -d '\n' < "$kernel_release_file")"
actual_release="$(tr -d '\n' < "$kernel_source_dir/include/config/kernel.release")"
[ "$actual_release" = "$kernel_release" ] || {
    echo "kernel release mismatch: $kernel_release != $actual_release" >&2
    exit 1
}
build_uid="$(id -u)"
build_gid="$(id -g)"

scratch="$(mktemp -d /tmp/tinfoil-nvidia-open.XXXXXXXX)"
: > "$scratch/.tinfoil-owned"
publish="$(mktemp -d "$kernel_out_dir/.nvidia-modules.XXXXXXXX")"
: > "$publish/.tinfoil-owned"
chmod 0755 "$publish"
chmod 0644 "$publish/.tinfoil-owned"
trap 'cleanup_owned "$scratch" /tmp tinfoil-nvidia-open; cleanup_owned "$publish" "$kernel_out_dir" .nvidia-modules' EXIT

resolve_package() {
    local package_name=$1 expected_sha256=$2
    local package_path="$package_cache_dir/$package_name"
    local downloaded_path="$scratch/$package_name"
    local cache_temporary

    if [ -L "$package_path" ] || { [ -e "$package_path" ] && [ ! -f "$package_path" ]; }; then
        echo "refusing invalid cached NVIDIA package: $package_path" >&2
        exit 1
    fi
    if [ -f "$package_path" ]; then
        printf '%s  %s\n' "$expected_sha256" "$package_path" | sha256sum -c --status - || {
            echo "cached NVIDIA package checksum mismatch: $package_path" >&2
            exit 1
        }
        install -m 0644 "$package_path" "$downloaded_path"
        printf '%s  %s\n' "$expected_sha256" "$downloaded_path" | sha256sum -c --status - || {
            echo "private NVIDIA package checksum mismatch: $package_name" >&2
            exit 1
        }
        printf '%s\n' "$downloaded_path"
        return 0
    fi
    if [ "${TINFOIL_OFFLINE:-0}" = 1 ]; then
        echo "missing pinned offline NVIDIA package: $package_name (expected $package_path)" >&2
        exit 1
    fi

    curl -fL --retry 3 --retry-delay 2 "$nvidia_repo_url/$package_name" -o "$downloaded_path"
    printf '%s  %s\n' "$expected_sha256" "$downloaded_path" | sha256sum -c --status - || {
        echo "downloaded NVIDIA package checksum mismatch: $package_name" >&2
        exit 1
    }
    cache_temporary="$(mktemp "$package_cache_dir/.$package_name.XXXXXXXX")"
    install -m 0644 "$downloaded_path" "$cache_temporary"
    printf '%s  %s\n' "$expected_sha256" "$cache_temporary" | sha256sum -c --status - || {
        rm -f -- "$cache_temporary"
        echo "staged NVIDIA package checksum mismatch: $package_name" >&2
        exit 1
    }
    mv -T -- "$cache_temporary" "$package_path"
    printf '%s\n' "$downloaded_path"
}
source_package="$(resolve_package "$source_deb" "$source_sha256")"
dkms_package="$(resolve_package "$dkms_deb" "$dkms_sha256")"

mkdir -p "$scratch/source" "$scratch/dkms"
dpkg-deb -x "$source_package" "$scratch/source"
dpkg-deb -x "$dkms_package" "$scratch/dkms"
nvidia_source_dir="$scratch/source/usr/src/nvidia-$nvidia_version"
patch_file="$scratch/dkms/usr/src/nvidia-$nvidia_version/patches/disable_fstack-clash-protection_fcf-protection.patch"
require_file "$nvidia_source_dir/Makefile" "NVIDIA source Makefile"
require_file "$patch_file" "NVIDIA DKMS patch"
patch --forward --batch -p1 -d "$nvidia_source_dir" < "$patch_file"
printf '%s\n' '#!/bin/sh' 'exec /usr/bin/pahole "$@"' > "$nvidia_source_dir/pahole.sh"
chmod 0755 "$nvidia_source_dir/pahole.sh"

mkdir -p "$scratch/built-modules"
if ! sudo unshare --mount --propagation private \
    "$kernel_dir/build-nvidia-open-canonical.sh" \
    "$kernel_source_dir" "$nvidia_source_dir" "$scratch/built-modules" "$kernel_release" \
    "$build_uid" "$build_gid" > "$scratch/build.log" 2>&1; then
    tail -n 200 "$scratch/build.log" >&2
    exit 1
fi

config_sha256="$(sha256sum "$kernel_source_dir/.config" | awk '{print $1}')"
symvers_sha256="$(sha256sum "$kernel_source_dir/vmlinux.symvers" | awk '{print $1}')"
source_revision="kernel:${kernel_release};config:${config_sha256};symvers:${symvers_sha256};nvidia:${nvidia_package_version};source-deb:${source_sha256};dkms-deb:${dkms_sha256}"
build_parameters='gcc=15.2.0-5ubuntu1;binutils=2.46-3ubuntu2;pahole=1.31-2ubuntu1;kmod=34.2-2ubuntu2;KBUILD_BUILD_TIMESTAMP=0;KBUILD_BUILD_USER=tinfoil;KBUILD_BUILD_HOST=tinfoil-builder;jobs=1;uncompressed;NV_EXCLUDE_KERNEL_MODULES=nvidia-drm,nvidia-peermem'
declare -A validated_vermagic=()
for module in "${required_modules[@]}"; do
    require_file "$scratch/built-modules/$module" "built NVIDIA module"
    vermagic="$(modinfo -F vermagic "$scratch/built-modules/$module")"
    case "$vermagic" in "$kernel_release "*) ;; *) echo "$module: unexpected vermagic: $vermagic" >&2; exit 1;; esac
    validated_vermagic["$module"]="${vermagic% }"
done

module_versions="$(modprobe --dump-modversions "$scratch/built-modules/nvidia.ko")"
for symbol in pci_iounmap iterate_fd init_pid_ns pci_restore_state; do
    expected="$(awk -v symbol="$symbol" '$2 == symbol { print $1; exit }' "$kernel_source_dir/Module.symvers")"
    actual="$(awk -v symbol="$symbol" '$2 == symbol { print $1; exit }' <<<"$module_versions")"
    [ -n "$expected" ] && [ "$expected" = "$actual" ] || {
        echo "module CRC mismatch for $symbol" >&2; exit 1
    }
done

mkdir -- "$publish/artifacts"
{
    printf '%s\n' '# rootfs artifact producer manifest v1'
    printf '%s\n' '# producer<TAB>name<TAB>kind<TAB>path<TAB>mode<TAB>uid<TAB>gid<TAB>sha256<TAB>link_target<TAB>destination<TAB>source_kind<TAB>source_revision<TAB>build_parameters'
    for module in "${required_modules[@]}"; do
        install -m 0644 "$scratch/built-modules/$module" "$publish/artifacts/$module"
        touch -d @0 "$publish/artifacts/$module"
        digest="$(sha256sum "$publish/artifacts/$module" | awk '{print $1}')"
        printf 'nvidia-modules\t%s\tfile\tartifacts/%s\t0644\t0\t0\t%s\t-\t/usr/lib/tinfoil/kernel-modules/%s\tsource-build\t%s\t%s;vermagic=%s\n' \
            "$module" "$module" "$digest" "$module" "$source_revision" "$build_parameters" "${validated_vermagic[$module]}"
    done
} > "$publish/rootfs-artifacts.tsv"
touch -d @0 "$publish/rootfs-artifacts.tsv"

output_parent="$(dirname -- "$output_dir")"
output_name="$(basename -- "$output_dir")"
[ "$output_dir" = "$output_parent/$output_name" ] || {
    echo "refusing non-canonical output path: $output_dir" >&2
    exit 1
}
if [ -L "$output_parent" ]; then
    echo "refusing symlinked rootfs-artifacts output parent: $output_parent" >&2
    exit 1
fi
if [ "$output_parent" = "$kernel_out_dir/rootfs-artifacts" ] && [ ! -e "$output_parent" ]; then
    mkdir -- "$output_parent"
fi
require_canonical_directory "$output_parent" "rootfs-artifacts output parent"
exec {output_parent_fd}<"$output_parent"
[ "$(realpath -e -- "/proc/self/fd/$output_parent_fd")" = "$output_parent" ] || {
    echo "rootfs-artifacts output parent changed while opening: $output_parent" >&2
    exit 1
}
output_parent_identity="$(stat -Lc '%d:%i' "/proc/self/fd/$output_parent_fd")"
[ "$(stat -Lc '%d:%i' "$output_parent")" = "$output_parent_identity" ] || {
    echo "rootfs-artifacts output parent identity changed: $output_parent" >&2
    exit 1
}
pinned_output_dir="/proc/self/fd/$output_parent_fd/$output_name"
if [ -L "$pinned_output_dir" ]; then
    echo "refusing symlinked output: $output_dir" >&2
    exit 1
fi
if [ -e "$pinned_output_dir" ]; then
    [ ! -L "$pinned_output_dir" ] && [ ! -L "$pinned_output_dir/.tinfoil-owned" ] && \
        [ -f "$pinned_output_dir/.tinfoil-owned" ] || {
        echo "refusing to replace unowned output: $output_dir" >&2; exit 1
    }
    rm -rf --one-file-system -- "$pinned_output_dir"
fi
[ "$(stat -Lc '%d:%i' "$output_parent")" = "$output_parent_identity" ] || {
    echo "rootfs-artifacts output parent changed before publication: $output_parent" >&2
    exit 1
}
mv -T -- "$publish" "$pinned_output_dir"
publish=
[ "$(stat -Lc '%d:%i' "$output_parent")" = "$output_parent_identity" ] || {
    rm -rf --one-file-system -- "$pinned_output_dir"
    echo "rootfs-artifacts output parent changed during publication: $output_parent" >&2
    exit 1
}
exec {output_parent_fd}<&-
printf 'NVIDIA rootfs artifacts: %s (%s)\n' "$output_dir" "$kernel_release"
