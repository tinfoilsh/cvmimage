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
replacement=
cleanup() {
    rm -rf -- "$scratch"
    if [ -n "$replacement" ]; then
        rm -f -- "$replacement"
    fi
}
trap cleanup EXIT

resolve_runtime_lock() {
    local workspace="$scratch/workspace"
    local output_base="$scratch/output-base"
    local generated="$scratch/generated"

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
        "$bazel_bin" --batch --output_base="$output_base" cquery \
            --lockfile_mode=error --output=files \
            '@@rules_distroless++apt+ubuntu_runtime_resolve//:lockfile' \
            > "$generated/cquery.out"
        mapfile -t outputs < "$generated/cquery.out"
        if [ "${#outputs[@]}" -ne 1 ] || [ -z "${outputs[0]}" ]; then
            printf 'expected one generated package lock, got %s\n' "${#outputs[@]}" >&2
            exit 1
        fi
        lockfile=${outputs[0]}
        case "$lockfile" in
            /*) ;;
            *)
                execution_root="$("$bazel_bin" --batch --output_base="$output_base" \
                    info --lockfile_mode=error execution_root)"
                lockfile="$execution_root/$lockfile"
                ;;
        esac
        cp -- "$lockfile" "$generated/runtime-packages.lock.json"
    )
}

resolve_runtime_lock
(cd "$repo_dir" && "$bazel_bin" mod deps --lockfile_mode=error >/dev/null)

if [ "$check_only" -eq 1 ]; then
    cmp "$scratch/generated/runtime-packages.lock.json" \
        "$repo_dir/image/runtime-packages.lock.json"
else
    replacement="$(mktemp "$repo_dir/image/.runtime-packages.lock.json.XXXXXXXX")"
    install -m 0644 "$scratch/generated/runtime-packages.lock.json" "$replacement"
    mv -f -- "$replacement" "$repo_dir/image/runtime-packages.lock.json"
    replacement=
fi
