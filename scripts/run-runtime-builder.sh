#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 {initrd|nvattest|kernel|nvidia}" >&2
    exit 2
fi

producer=$1
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"
base_image="$(<"$repo_dir/scripts/runtime-builder-base-image.txt")"
snapshot="$(<"$repo_dir/scripts/runtime-builder-snapshot.txt")"
builder_image="cvmimage-runtime-builder:${snapshot%%T*}"
host_uid="$(id -u)"
host_gid="$(id -g)"
cache_root="${TINFOIL_RUNTIME_BUILDER_CACHE:-$repo_dir/build/runtime-builder-cache}"
recipe_sha256="$(
    cd "$repo_dir"
    sha256sum \
        builder/Dockerfile \
        builder/build-initrd.sh \
        scripts/runtime-builder-base-image.txt \
        scripts/runtime-builder-snapshot.txt | sha256sum | awk '{print $1}'
)"

if [[ ! "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
    echo "invalid runtime builder snapshot: $snapshot" >&2
    exit 1
fi

actual_base="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.base" }}' "$builder_image" 2>/dev/null || true)"
actual_snapshot="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.snapshot" }}' "$builder_image" 2>/dev/null || true)"
actual_recipe="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.recipe" }}' "$builder_image" 2>/dev/null || true)"
if [ "$actual_base" != "$base_image" ] ||
    [ "$actual_snapshot" != "$snapshot" ] ||
    [ "$actual_recipe" != "$recipe_sha256" ]; then
    echo "missing or stale runtime builder; run scripts/build-runtime-builder.sh" >&2
    exit 1
fi

mkdir -p "$cache_root"
repo_mount="type=bind,src=$repo_dir,dst=/workspace,readonly"

case "$producer" in
    initrd)
        output="${TINFOIL_BUILDER_OUTPUT:-$repo_dir/build/builder-work/output}"
        mkdir -p "$output" "$cache_root/go-build" "$cache_root/go-mod"
        docker run --rm \
            --user "$host_uid:$host_gid" \
            --mount "$repo_mount" \
            --mount "type=bind,src=$output,dst=/output" \
            --mount "type=bind,src=$cache_root/go-build,dst=/cache/go-build" \
            --mount "type=bind,src=$cache_root/go-mod,dst=/cache/go-mod" \
            --env GOCACHE=/cache/go-build \
            --env GOMODCACHE=/cache/go-mod \
            "$builder_image" \
            /usr/local/bin/build-initrd /workspace /output
        ;;
    nvattest)
        deb_output="${TINFOIL_NVATTEST_DEB_OUTPUT:-$repo_dir/packages}"
        runtime_output="${TINFOIL_NVATTEST_RUNTIME_OUTPUT:-$repo_dir/build/rootfs-artifacts/nvattest}"
        nvattest_home="$cache_root/nvattest-home"
        mkdir -p "$deb_output" "$runtime_output" "$nvattest_home"
        docker run --rm \
            --user "$host_uid:$host_gid" \
            --mount "$repo_mount" \
            --mount "type=bind,src=$deb_output,dst=/output/debs" \
            --mount "type=bind,src=$runtime_output,dst=/output/runtime" \
            --mount "type=bind,src=$nvattest_home,dst=/builder-home" \
            --env HOME=/builder-home \
            --env CARGO_HOME=/builder-home/cargo \
            --env "HOST_UID=$host_uid" \
            --env "HOST_GID=$host_gid" \
            "$builder_image" \
            /workspace/build-nvattest.sh \
                --deb-output /output/debs \
                --runtime-output /output/runtime
        ;;
    kernel)
        source "$kernel_dir/profile.sh"
        select_tinfoil_kernel_profile
        build_root="$kernel_build_root"
        output="$kernel_out_dir"
        mkdir -p "$build_root" "$output"
        docker run --rm \
            --user "$host_uid:$host_gid" \
            --mount "$repo_mount" \
            --mount "type=bind,src=$build_root,dst=/kernel-build" \
            --mount "type=bind,src=$output,dst=/kernel-output" \
            --env TINFOIL_KERNEL_BUILD_ROOT=/kernel-build \
            --env TINFOIL_KERNEL_OUT_DIR=/kernel-output \
            --env "TINFOIL_KERNEL_PROFILE=$kernel_profile" \
            --env TINFOIL_KERNEL_SOURCE_DEB=/opt/tinfoil-builder/packages/linux-source-7.0.0_7.0.0-28.28_all.deb \
            --env TINFOIL_OFFLINE=1 \
            "$builder_image" \
            /workspace/kernel/build-local.sh
        ;;
    nvidia)
        source "$kernel_dir/profile.sh"
        select_tinfoil_kernel_profile
        if [ "$kernel_profile" != release ]; then
            echo "NVIDIA modules are not defined for kernel profile: $kernel_profile" >&2
            exit 2
        fi
        build_root="$kernel_build_root"
        kernel_output="$kernel_out_dir"
        output="${TINFOIL_NVIDIA_OUTPUT_DIR:-$kernel_output/rootfs-artifacts/nvidia-modules}"
        output_parent="$(dirname -- "$output")"
        output_name="$(basename -- "$output")"
        package_cache="${TINFOIL_NVIDIA_PACKAGE_CACHE:-$cache_root/nvidia-packages}"
        mkdir -p "$build_root" "$kernel_output" "$output_parent" "$package_cache"
        docker run --rm \
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
            --env "TINFOIL_KERNEL_PROFILE=$kernel_profile" \
            --env "TINFOIL_NVIDIA_OUTPUT_DIR=/nvidia-output-parent/$output_name" \
            --env TINFOIL_NVIDIA_PACKAGE_CACHE=/nvidia-cache \
            --env "TINFOIL_OFFLINE=${TINFOIL_OFFLINE:-0}" \
            "$builder_image" \
            /workspace/kernel/build-nvidia-open-local.sh
        ;;
    *)
        echo "unknown runtime producer: $producer" >&2
        exit 2
        ;;
esac
