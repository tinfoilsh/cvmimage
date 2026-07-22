#!/usr/bin/env bash
set -Eeuo pipefail

PATH=/usr/local/bin:/usr/bin:/bin
export PATH LC_ALL=C

cleanup_runtime_lock_tree() {
    local directory=$1
    local expected_token=$2
    local resolved marker owner mode token
    [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
    resolved=$(realpath -e -- "$directory") || return 1
    case "$resolved" in
        /tmp/cvmimage-runtime-lock.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
        *) return 1 ;;
    esac
    [ "$resolved" = "$directory" ] || return 1
    marker="$resolved/.cvmimage-runtime-lock-owner"
    [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
    owner=$(stat -c %u -- "$resolved") || return 1
    mode=$(stat -c %a -- "$resolved") || return 1
    [ "$owner" = "$(id -u)" ] && [ "$mode" = 700 ] || return 1
    IFS= read -r token < "$marker" || return 1
    [ "$token" = "$expected_token" ] || return 1
    chmod -R u+rwx -- "$resolved"
    rm -rf --one-file-system -- "$resolved"
}

if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
fi

check_only=0
case ${1:-} in
    "") ;;
    --check) check_only=1 ;;
    *) echo "usage: update-runtime-locks.sh [--check]" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo "usage: update-runtime-locks.sh [--check]" >&2; exit 2; }

repo_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
bazel_bin=${BAZEL:-bazel}
if [ "$("$bazel_bin" --version)" != "bazel 8.7.0" ]; then
    echo "runtime lock update requires Bazel 8.7.0" >&2
    exit 1
fi

umask 077
scratch=$(mktemp -d /tmp/cvmimage-runtime-lock.XXXXXXXX)
scratch=$(realpath -e -- "$scratch")
cleanup_token="$(id -u):$$:$RANDOM:$RANDOM"
printf '%s\n' "$cleanup_token" > "$scratch/.cvmimage-runtime-lock-owner"
tree_a=$scratch/a
tree_b=$scratch/b
mkdir -m 0700 -- "$tree_a" "$tree_b"
trap 'cleanup_runtime_lock_tree "$scratch" "$cleanup_token"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

prepare_resolver() {
    local tree=$1
    mkdir -p -- "$tree/workspace/image" "$tree/generated" "$tree/downloads"
    cp -- "$repo_dir/image/runtime-packages.yaml" "$tree/workspace/image/runtime-packages.yaml"
    cp -- "$repo_dir/image/runtime-sources.lock.json" "$tree/workspace/image/runtime-sources.lock.json"
    cat > "$tree/workspace/MODULE.bazel" <<'EOF'
module(name = "cvmimage_lock_update", version = "0.0.0")
bazel_dep(name = "rules_distroless", version = "0.8.0")
apt = use_extension("@rules_distroless//apt:extensions.bzl", "apt")
apt.install(name = "ubuntu_runtime", manifest = "//image:runtime-packages.yaml")
use_repo(apt, "ubuntu_runtime")
EOF
    cat > "$tree/workspace/BUILD.bazel" <<'EOF'
exports_files(["MODULE.bazel.lock"])
EOF
    cat > "$tree/workspace/image/BUILD.bazel" <<'EOF'
exports_files(["runtime-packages.yaml"])
EOF
}

resolve_once() {
    local tree=$1
    local workspace="$tree/workspace"
    local output_base="$tree/output-base"
    prepare_resolver "$tree"
    (
        cd "$workspace"
        "$bazel_bin" --batch --output_base="$output_base" build --lockfile_mode=update \
            '@@rules_distroless++apt+ubuntu_runtime_resolve//:lockfile'
        "$bazel_bin" --batch --output_base="$output_base" cquery --lockfile_mode=error --output=files \
            '@@rules_distroless++apt+ubuntu_runtime_resolve//:lockfile' > "$tree/cquery.out"
        mapfile -t outputs < "$tree/cquery.out"
        if [ "${#outputs[@]}" -ne 1 ] || [ -z "${outputs[0]}" ]; then
            printf 'expected one generated package lock, got %s\n' "${#outputs[@]}" >&2
            exit 1
        fi
        execution_root=$("$bazel_bin" --batch --output_base="$output_base" info --lockfile_mode=error execution_root)
        cp -- "$execution_root/${outputs[0]}" "$tree/generated/runtime-packages.lock.json"
    )
    python3 "$repo_dir/scripts/runtime_source_lock.py" canonicalize \
        "$tree/workspace/image/runtime-sources.lock.json" \
        "$tree/generated/runtime-sources.lock.json" \
        "$tree/downloads"
    python3 "$repo_dir/scripts/runtime_source_lock.py" validate-dependencies \
        "$tree/generated/runtime-sources.lock.json" \
        "$tree/generated/runtime-packages.lock.json"
    cp -- "$repo_dir/MODULE.bazel" "$tree/workspace/MODULE.bazel"
    cp -- "$tree/generated/runtime-packages.lock.json" "$tree/workspace/image/runtime-packages.lock.json"
    cat > "$tree/workspace/image/BUILD.bazel" <<'EOF'
exports_files(["runtime-packages.lock.json", "runtime-packages.yaml"])
EOF
    rm -f -- "$tree/workspace/MODULE.bazel.lock"
    (
        cd "$tree/workspace"
        "$bazel_bin" --batch --output_base="$tree/module-output-base" mod graph \
            --lockfile_mode=update > "$tree/module-graph.out"
        cp -- MODULE.bazel.lock "$tree/generated/MODULE.bazel.lock"
    )
}

resolve_once "$tree_a"
resolve_once "$tree_b"

cmp -- "$tree_a/generated/runtime-packages.lock.json" "$tree_b/generated/runtime-packages.lock.json"
cmp -- "$tree_a/generated/MODULE.bazel.lock" "$tree_b/generated/MODULE.bazel.lock"
cmp -- "$tree_a/generated/runtime-sources.lock.json" "$tree_b/generated/runtime-sources.lock.json"

if [ "$check_only" -eq 1 ]; then
    cmp -- "$tree_a/generated/runtime-packages.lock.json" "$repo_dir/image/runtime-packages.lock.json"
    cmp -- "$tree_a/generated/runtime-sources.lock.json" "$repo_dir/image/runtime-sources.lock.json"
    cmp -- "$tree_a/generated/MODULE.bazel.lock" "$repo_dir/MODULE.bazel.lock"
else
    python3 "$repo_dir/scripts/runtime_source_lock.py" atomic-replace \
        "$tree_a/generated/runtime-packages.lock.json" "$repo_dir/image/runtime-packages.lock.json"
    python3 "$repo_dir/scripts/runtime_source_lock.py" atomic-replace \
        "$tree_a/generated/runtime-sources.lock.json" "$repo_dir/image/runtime-sources.lock.json"
    python3 "$repo_dir/scripts/runtime_source_lock.py" atomic-replace \
        "$tree_a/generated/MODULE.bazel.lock" "$repo_dir/MODULE.bazel.lock"
fi
