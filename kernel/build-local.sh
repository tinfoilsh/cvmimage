#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"

kernel_source_version="7.0.0"
kernel_package_version="7.0.0-28.28"
kernel_source_deb_sha256="dd5994b199a1cb06b1f336bb086c5c23a9258fdcfdcbb7dcc8d3afa9a5d92e13"
kernel_version_override="$kernel_source_version"
defconfig="$kernel_dir/tinfoil-cvm-7.0.defconfig"

source "$kernel_dir/profile.sh"
select_tinfoil_kernel_profile

build_root="$kernel_build_root"
out_dir="$kernel_out_dir"
source_dir="$build_root/linux-source-${kernel_source_version}"
source_package_root="$build_root/source-package"
make_version_args=(KERNELVERSION="$kernel_version_override")

find_source_deb() {
    local deb_name="$1"
    local candidate
    for candidate in \
        "${TINFOIL_KERNEL_SOURCE_DEB:-}" \
        "$build_root/debs/$deb_name" \
        "/var/cache/apt/archives/$deb_name"; do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

extract_pinned_source_tarball() {
    local deb_name="linux-source-${kernel_source_version}_${kernel_package_version}_all.deb"
    local source_deb
    source_deb="$(find_source_deb "$deb_name" || true)"
    if [ -z "$source_deb" ]; then
        if [ "${TINFOIL_OFFLINE:-0}" = 1 ]; then
            echo "missing pinned offline kernel source package: $deb_name" >&2
            exit 1
        fi
        mkdir -p "$build_root/debs"
        (
            cd "$build_root/debs"
            apt-get download "linux-source-${kernel_source_version}=${kernel_package_version}"
        ) >&2
        source_deb="$build_root/debs/$deb_name"
    fi
    if [ ! -f "$source_deb" ]; then
        cat >&2 <<EOF
missing pinned kernel source package: $deb_name

Download it first, or point TINFOIL_KERNEL_SOURCE_DEB at the package:
  apt-get download linux-source-${kernel_source_version}=${kernel_package_version}
EOF
        exit 1
    fi
    printf '%s  %s\n' "$kernel_source_deb_sha256" "$source_deb" | sha256sum -c --status -

    rm -rf "$source_package_root"
    mkdir -p "$source_package_root"
    dpkg-deb -x "$source_deb" "$source_package_root"

    local candidate
    for candidate in \
        "$source_package_root/usr/src/linux-source-${kernel_source_version}.tar.xz" \
        "$source_package_root/usr/src/linux-source-${kernel_source_version}.tar.bz2" \
        "$source_package_root/usr/src/linux-source-${kernel_source_version}/linux-source-${kernel_source_version}.tar.xz" \
        "$source_package_root/usr/src/linux-source-${kernel_source_version}/linux-source-${kernel_source_version}.tar.bz2"; do
        if [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    echo "pinned source package did not contain a linux-source-${kernel_source_version} tarball" >&2
    exit 1
}

if [ ! -f "$defconfig" ]; then
    echo "missing Tinfoil kernel defconfig: $defconfig" >&2
    exit 1
fi

mkdir -p "$build_root" "$out_dir"
source_tarball="$(extract_pinned_source_tarball)"

rm -rf "$source_dir"
tar -xaf "$source_tarball" -C "$build_root"
sed -i 's/--build-id=sha1/--build-id=none/g' \
    "$source_dir/Makefile" \
    "$source_dir/arch/x86/entry/vdso/common/Makefile.include"

echo "Kernel source: $source_dir"
echo "Kernel source tarball: $source_tarball"
echo "Tinfoil defconfig: $defconfig"
echo "Kernel profile: $kernel_profile"
shopt -s nullglob
policy_fragments=("$kernel_dir"/config.d/*.config)
if [ "${#policy_fragments[@]}" -eq 0 ]; then
    echo "no kernel policy fragments found under $kernel_dir/config.d" >&2
    exit 1
fi
policy_fragments+=("$kernel_profile_fragment")
echo "Policy fragments:"
printf '  %s\n' "${policy_fragments[@]}"

(
    cd "$source_dir"
    install -m 0644 "$defconfig" arch/x86/configs/tinfoil_cvm_defconfig
    make "${make_version_args[@]}" tinfoil_cvm_defconfig
    ./scripts/kconfig/merge_config.sh -m .config "${policy_fragments[@]}"
    make "${make_version_args[@]}" olddefconfig
)

"$kernel_dir/check-config.sh" "$source_dir/.config" "${policy_fragments[@]}"

export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-$(date -u -d @0)}"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-tinfoil}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-tinfoil-builder}"

make -C "$source_dir" "${make_version_args[@]}" \
    -j "${TINFOIL_KERNEL_JOBS:-$(nproc)}" bzImage
make -C "$source_dir" "${make_version_args[@]}" modules_prepare

kernel_release="$(make -s -C "$source_dir" "${make_version_args[@]}" kernelrelease)"
if [ "$kernel_release" != "$kernel_expected_release" ]; then
    cat >&2 <<EOF
kernel release mismatch
  built:    $kernel_release
  expected: $kernel_expected_release

Keep the custom kernel release aligned with the external NVIDIA module tree.
EOF
    exit 1
fi
install -m 0644 "$source_dir/arch/x86/boot/bzImage" "$out_dir/tinfoil-custom.vmlinuz"
install -m 0644 "$source_dir/.config" "$out_dir/config"
printf '%s\n' "$kernel_release" > "$out_dir/kernel.release"
printf '%s\n' "$kernel_profile" > "$out_dir/profile"
if [ ! -s "$source_dir/vmlinux.symvers" ]; then
    echo "missing required kernel symbol versions: $source_dir/vmlinux.symvers" >&2
    exit 1
fi
install -m 0644 "$source_dir/vmlinux.symvers" "$source_dir/Module.symvers"
install -m 0644 "$source_dir/Module.symvers" "$out_dir/Module.symvers"
if [ ! -s "$source_dir/modules.builtin" ]; then
    echo "missing required built-in module inventory: $source_dir/modules.builtin" >&2
    exit 1
fi
install -m 0644 "$source_dir/modules.builtin" "$out_dir/modules.builtin"

sha256sum "$out_dir/tinfoil-custom.vmlinuz" "$out_dir/config" "$out_dir/modules.builtin" "$out_dir/Module.symvers" "$out_dir/profile" > "$out_dir/checksums.sha256"

cat <<EOF
custom kernel build complete
  release: $kernel_release
  profile: $kernel_profile
  kernel:  $out_dir/tinfoil-custom.vmlinuz
  config:  $out_dir/config
  builtins:$out_dir/modules.builtin
  symvers: $out_dir/Module.symvers
EOF
