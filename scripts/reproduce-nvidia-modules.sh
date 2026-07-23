#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
reproduction_dir="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-nvidia-repro.XXXXXXXX")"
trap 'rm -rf -- "$reproduction_dir"' EXIT

"$repo_dir/scripts/build-runtime-builder.sh"

build_once() {
    local name=$1
    local root="$reproduction_dir/$name"

    mkdir -p "$root"
    TINFOIL_KERNEL_BUILD_ROOT="$root/kernel-build/release" \
        TINFOIL_KERNEL_OUT_DIR="$root/kernel-output/release" \
        TINFOIL_RUNTIME_BUILDER_CACHE="$root/cache" \
        "$repo_dir/scripts/run-runtime-builder.sh" kernel
    TINFOIL_KERNEL_BUILD_ROOT="$root/kernel-build/release" \
        TINFOIL_KERNEL_OUT_DIR="$root/kernel-output/release" \
        TINFOIL_NVIDIA_OUTPUT_DIR="$root/nvidia-modules" \
        TINFOIL_NVIDIA_PACKAGE_CACHE="$root/nvidia-packages" \
        TINFOIL_RUNTIME_BUILDER_CACHE="$root/cache" \
        "$repo_dir/scripts/run-runtime-builder.sh" nvidia
}

build_once first
build_once second
while IFS= read -r module; do
    cmp "$reproduction_dir/first/nvidia-modules/$module" \
        "$reproduction_dir/second/nvidia-modules/$module"
done < "$repo_dir/kernel/nvidia-modules.txt"
cmp "$reproduction_dir/first/nvidia-modules/BUILD.bazel" \
    "$reproduction_dir/second/nvidia-modules/BUILD.bazel"

echo "NVIDIA modules are byte-identical across isolated builds"
