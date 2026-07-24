#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/bazel-rootfs.tar" >&2
    exit 2
fi

archive="$1"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

members="$scratch/members"
tar -tf "$archive" | sed 's#^\./##' >"$members"

forbidden_paths=(
    usr/lib/x86_64-linux-gnu/libnvidia-egl-gbm.so.1
    usr/lib/x86_64-linux-gnu/libnvidia-egl-gbm.so.1.1.3
    usr/lib/x86_64-linux-gnu/libnvidia-egl-wayland2.so.1
    usr/lib/x86_64-linux-gnu/libnvidia-egl-wayland2.so.1.0.1
    usr/lib/x86_64-linux-gnu/libnvidia-egl-xcb.so.1
    usr/lib/x86_64-linux-gnu/libnvidia-egl-xcb.so.1.0.5
    usr/lib/x86_64-linux-gnu/libnvidia-egl-xlib.so.1
    usr/lib/x86_64-linux-gnu/libnvidia-egl-xlib.so.1.0.5
    usr/lib/x86_64-linux-gnu/libnvidia-encode.so
    usr/lib/x86_64-linux-gnu/libnvidia-encode.so.1
    usr/lib/x86_64-linux-gnu/libnvidia-encode.so.595.71.05
    usr/share/doc/libnvidia-egl-gbm1/
    usr/share/doc/libnvidia-egl-wayland21/
    usr/share/doc/libnvidia-egl-xcb1/
    usr/share/doc/libnvidia-egl-xlib1/
    usr/share/doc/libnvidia-encode/
    usr/share/egl/egl_external_platform.d/09_nvidia_wayland2.json
    usr/share/egl/egl_external_platform.d/15_nvidia_gbm.json
    usr/share/egl/egl_external_platform.d/20_nvidia_xcb.json
    usr/share/egl/egl_external_platform.d/20_nvidia_xlib.json
)
for path in "${forbidden_paths[@]}"; do
    if grep -Fqx "$path" "$members"; then
        echo "$path must not be present in the compute-only rootfs" >&2
        exit 1
    fi
done

required_paths=(
    etc/nvidia-container-runtime/config.toml
    usr/bin/nv-fabricmanager
    usr/bin/nvattest
    usr/bin/nvidia-container-cli
    usr/bin/nvidia-container-runtime
    usr/bin/nvidia-ctk
    usr/lib/x86_64-linux-gnu/libcuda.so.595.71.05
    usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2
    usr/lib/x86_64-linux-gnu/libnvcuvid.so.595.71.05
    usr/lib/x86_64-linux-gnu/libnvfm.so.1
    usr/lib/x86_64-linux-gnu/libnvidia-ml.so.595.71.05
    usr/lib/x86_64-linux-gnu/libnvidia-opticalflow.so.595.71.05
)
for path in "${required_paths[@]}"; do
    if [[ "$(grep -Fxc "$path" "$members")" -ne 1 ]]; then
        echo "$path must appear exactly once in the compute-only rootfs" >&2
        exit 1
    fi
done
