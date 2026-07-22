#!/usr/bin/env bash
set -Eeuo pipefail

check_only=0
case ${1:-} in
    "") ;;
    --check) check_only=1 ;;
    *) echo "usage: update-runtime-locks.sh [--check]" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo "usage: update-runtime-locks.sh [--check]" >&2; exit 2; }

repo_dir="$(cd -- "$(dirname -- "$0")/.." && pwd)"
bazel_bin="${BAZEL:-bazel}"
if [ "$("$bazel_bin" --version)" != "bazel 8.7.0" ]; then
    echo "runtime lock update requires Bazel 8.7.0" >&2
    exit 1
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-runtime-lock.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

resolve_once() {
    local name=$1
    local workspace="$scratch/$name/workspace"
    local output_base="$scratch/$name/output-base"
    local generated="$scratch/$name/generated"

    mkdir -p "$workspace/image" "$generated"
    cp "$repo_dir/image/runtime-packages.yaml" "$workspace/image/"
    cat > "$workspace/MODULE.bazel" <<'EOF'
module(name = "cvmimage_lock_update", version = "0.0.0")
bazel_dep(name = "rules_distroless", version = "0.8.0")
apt = use_extension("@rules_distroless//apt:extensions.bzl", "apt")
apt.install(name = "ubuntu_runtime", manifest = "//image:runtime-packages.yaml")
use_repo(apt, "ubuntu_runtime")
EOF
    printf '%s\n' 'package(default_visibility = ["//visibility:public"])' > "$workspace/BUILD.bazel"
    printf '%s\n' 'exports_files(["runtime-packages.yaml"])' > "$workspace/image/BUILD.bazel"

    (
        cd "$workspace"
        "$bazel_bin" --batch --output_base="$output_base" build --lockfile_mode=update \
            '@@rules_distroless++apt+ubuntu_runtime_resolve//:lockfile'
        lockfile="$("$bazel_bin" --batch --output_base="$output_base" cquery \
            --lockfile_mode=error --output=files \
            '@@rules_distroless++apt+ubuntu_runtime_resolve//:lockfile')"
        case "$lockfile" in
            /*) ;;
            *) lockfile="$output_base/$lockfile" ;;
        esac
        cp "$lockfile" "$generated/runtime-packages.lock.json"
    )
}

resolve_once first
resolve_once second
cmp "$scratch/first/generated/runtime-packages.lock.json" \
    "$scratch/second/generated/runtime-packages.lock.json"

if [ "$check_only" -eq 1 ]; then
    cmp "$scratch/first/generated/runtime-packages.lock.json" \
        "$repo_dir/image/runtime-packages.lock.json"
else
    install -m 0644 "$scratch/first/generated/runtime-packages.lock.json" \
        "$repo_dir/image/runtime-packages.lock.json"
fi

(cd "$repo_dir" && "$bazel_bin" mod deps --lockfile_mode=error >/dev/null)
