#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 {debug-init|runtime-go|nvattest|kernel|nvidia}" >&2
    exit 2
fi

producer=$1
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
builder_image=cvmimage-runtime-builder
host_uid="$(id -u)"
host_gid="$(id -g)"
cache_root="$repo_dir/build/runtime-builder-cache"
repo_mount="type=bind,src=$repo_dir,dst=/workspace,readonly"

mkdir -p "$cache_root"

case "$producer" in
    debug-init)
        output="$repo_dir/build/debug-work/output"
        mkdir -p "$output" "$cache_root/go-build" "$cache_root/go-mod"
        docker run --pull=never --rm \
            --user "$host_uid:$host_gid" \
            --mount "$repo_mount" \
            --mount "type=bind,src=$output,dst=/output" \
            --mount "type=bind,src=$cache_root/go-build,dst=/cache/go-build" \
            --mount "type=bind,src=$cache_root/go-mod,dst=/cache/go-mod" \
            --env GOCACHE=/cache/go-build \
            --env GOMODCACHE=/cache/go-mod \
            "$builder_image" \
            /workspace/builder/build-debug-init.sh /workspace /output
        ;;
    runtime-go)
        output="$repo_dir/build/builder-work/output"
        mkdir -p "$output" "$cache_root/go-build" "$cache_root/go-mod"
        docker run --pull=never --rm \
            --user "$host_uid:$host_gid" \
            --mount "$repo_mount" \
            --mount "type=bind,src=$output,dst=/output" \
            --mount "type=bind,src=$cache_root/go-build,dst=/cache/go-build" \
            --mount "type=bind,src=$cache_root/go-mod,dst=/cache/go-mod" \
            --env GOCACHE=/cache/go-build \
            --env GOMODCACHE=/cache/go-mod \
            "$builder_image" \
            /usr/local/bin/build-runtime-go /workspace /output
        ;;
    nvattest)
        runtime_output="$repo_dir/build/rootfs-artifacts/nvattest"
        nvattest_home="$cache_root/nvattest-home"
        mkdir -p "$runtime_output" "$nvattest_home"
        docker run --pull=never --rm \
            --user "$host_uid:$host_gid" \
            --mount "$repo_mount" \
            --mount "type=bind,src=$runtime_output,dst=/output/runtime" \
            --mount "type=bind,src=$nvattest_home,dst=/builder-home" \
            --env HOME=/builder-home \
            --env CARGO_HOME=/builder-home/cargo \
            --env "HOST_UID=$host_uid" \
            --env "HOST_GID=$host_gid" \
            "$builder_image" \
            /workspace/builder/nvattest/build.sh --runtime-output /output/runtime
        ;;
    kernel)
        build_root="$repo_dir/kernel/build"
        output="$repo_dir/kernel/out"
        mkdir -p "$build_root" "$output"
        docker run --pull=never --rm \
            --user "$host_uid:$host_gid" \
            --mount "$repo_mount" \
            --mount "type=bind,src=$build_root,dst=/kernel-build" \
            --mount "type=bind,src=$output,dst=/kernel-output" \
            --env TINFOIL_KERNEL_BUILD_ROOT=/kernel-build \
            --env TINFOIL_KERNEL_OUT_DIR=/kernel-output \
            --env TINFOIL_KERNEL_SOURCE_DEB=/opt/tinfoil-builder/packages/linux-source-7.0.0_7.0.0-28.28_all.deb \
            --env TINFOIL_OFFLINE=1 \
            "$builder_image" \
            /workspace/kernel/build-local.sh
        ;;
    nvidia)
        build_root="$repo_dir/kernel/build"
        kernel_output="$repo_dir/kernel/out"
        output_parent="$kernel_output/rootfs-artifacts"
        package_cache="$cache_root/nvidia-packages"
        mkdir -p "$build_root" "$kernel_output" "$output_parent" "$package_cache"
        docker run --pull=never --rm \
            --cap-add SYS_ADMIN \
            --security-opt apparmor=unconfined \
            --security-opt seccomp=unconfined \
            --mount "$repo_mount" \
            --mount "type=bind,src=$build_root,dst=/kernel-build" \
            --mount "type=bind,src=$kernel_output,dst=/kernel-output" \
            --mount "type=bind,src=$output_parent,dst=/nvidia-output-parent" \
            --mount "type=bind,src=$package_cache,dst=/nvidia-cache" \
            --env "HOST_UID=$host_uid" \
            --env "HOST_GID=$host_gid" \
            --env TINFOIL_KERNEL_BUILD_ROOT=/kernel-build \
            --env TINFOIL_KERNEL_OUT_DIR=/kernel-output \
            --env TINFOIL_NVIDIA_OUTPUT_DIR=/nvidia-output-parent/nvidia-modules \
            --env TINFOIL_NVIDIA_PACKAGE_CACHE=/nvidia-cache \
            --env TINFOIL_OFFLINE=0 \
            "$builder_image" \
            /workspace/kernel/build-nvidia-open-local.sh
        ;;
    *)
        echo "unknown runtime producer: $producer" >&2
        exit 2
        ;;
esac
