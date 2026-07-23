#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-nvidia-producer-test.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

TINFOIL_NVIDIA_PACKAGE_CACHE="$scratch/package-cache"
source "$repo_dir/kernel/build-nvidia-open-local.sh"

release=7.0.0-28-generic
source_dir="$scratch/kernel"
module_dir="$scratch/modules"
mkdir -p "$source_dir" "$module_dir"

cat > "$source_dir/vmlinux.symvers" <<'EOF'
0x00000001 pci_iounmap
0x00000002 iterate_fd
0x00000003 init_pid_ns
0x00000004 pci_restore_state
EOF
for module in "${required_modules[@]}"; do
    printf module > "$module_dir/$module"
done

module_vermagic() {
    printf '%s SMP preempt mod_unload modversions\n' "$release"
}

module_versions() {
    cat <<'EOF'
0x00000001 pci_iounmap
0x00000002 iterate_fd
0x00000003 init_pid_ns
0x00000004 pci_restore_state
EOF
}

expect_failure() {
    local label=$1
    shift
    if ("$@") > "$scratch/failure.log" 2>&1; then
        echo "accepted $label" >&2
        exit 1
    fi
}

mkdir -p "$package_cache_dir"
printf 'expected package\n' > "$package_cache_dir/valid.deb"
expected_sha256="$(sha256sum "$package_cache_dir/valid.deb" | awk '{print $1}')"
resolved_package="$(download_deb valid.deb "$expected_sha256")"
test "$resolved_package" = "$package_cache_dir/valid.deb"

printf 'corrupt package\n' > "$package_cache_dir/cached.deb"
expected_sha256="$(printf 'expected package\n' | sha256sum | awk '{print $1}')"
expect_failure \
    "a cached NVIDIA package with a checksum mismatch" \
    download_deb cached.deb "$expected_sha256"
test ! -e "$package_cache_dir/cached.deb"
grep -Fq 'FAILED' "$scratch/failure.log"
grep -Fq 'removing NVIDIA package with checksum mismatch' "$scratch/failure.log"

validate_nvidia_modules "$source_dir" "$module_dir" "$release"

bazel_package="$scratch/bazel-package"
mkdir -p "$bazel_package"
write_bazel_module_package "$bazel_package"
cat > "$scratch/expected-BUILD.bazel" <<'EOF'
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "modules",
    srcs = [
        "nvidia.ko",
        "nvidia-uvm.ko",
        "nvidia-modeset.ko",
    ],
)
EOF
cmp "$scratch/expected-BUILD.bazel" "$bazel_package/BUILD.bazel"

for module in "${required_modules[@]}"; do
    mv "$module_dir/$module" "$module_dir/$module.missing"
    expect_failure "missing $module" validate_nvidia_modules "$source_dir" "$module_dir" "$release"
    mv "$module_dir/$module.missing" "$module_dir/$module"
done

(
    module_vermagic() { printf '%s\n' 'wrong-release SMP'; }
    expect_failure "wrong vermagic" validate_nvidia_modules "$source_dir" "$module_dir" "$release"
)

(
    module_versions() {
        cat <<'EOF'
0x00000001 pci_iounmap
0x00000002 iterate_fd
0x00000003 init_pid_ns
0x00000005 pci_restore_state
EOF
    }
    expect_failure "wrong symbol CRC" validate_nvidia_modules "$source_dir" "$module_dir" "$release"
)

echo "NVIDIA named module producer tests passed"
