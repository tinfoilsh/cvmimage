#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
reproduction_parent="$repo_dir/kernel/out"
mkdir -p "$reproduction_parent"
[ -d "$reproduction_parent" ] && [ ! -L "$reproduction_parent" ] || {
    echo "invalid NVIDIA reproduction parent: $reproduction_parent" >&2
    exit 1
}
temporary="$(mktemp -d "$reproduction_parent/.nvidia-module-repro.XXXXXXXX")"
: > "$temporary/.tinfoil-owned"
cleanup() {
    [ ! -L "$temporary" ] && [ -f "$temporary/.tinfoil-owned" ] || {
        echo "refusing to clean unowned reproduction directory" >&2
        return 1
    }
    case "$(realpath -e "$temporary")" in "$(realpath -e "$reproduction_parent")"/.nvidia-module-repro.*) ;; *) return 1;; esac
    find "$temporary" -depth -delete
}
trap cleanup EXIT

build_once() {
    local name=$1
    local build_root="$temporary/$name/kernel-build"
    local kernel_output="$temporary/$name/kernel-output"
    local module_output="$temporary/$name/nvidia-output"
    mkdir -p "$build_root" "$kernel_output"
    TINFOIL_KERNEL_BUILD_ROOT="$build_root" \
        TINFOIL_KERNEL_OUT_DIR="$kernel_output" \
        "$repo_dir/kernel/build-local.sh"
    TINFOIL_KERNEL_BUILD_ROOT="$build_root" \
        TINFOIL_KERNEL_OUT_DIR="$kernel_output" \
        TINFOIL_NVIDIA_OUTPUT_DIR="$module_output" \
        "$repo_dir/kernel/build-nvidia-open-local.sh"
}

build_once one
build_once two
for path in rootfs-artifacts.tsv artifacts/nvidia.ko artifacts/nvidia-uvm.ko artifacts/nvidia-modeset.ko; do
    cmp "$temporary/one/nvidia-output/$path" "$temporary/two/nvidia-output/$path"
done
printf 'NVIDIA module artifacts are byte-identical across isolated builds\n'
