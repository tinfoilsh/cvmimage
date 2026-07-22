#!/bin/bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

grep -Fqx 'prepare-runtime-artifacts: verify-rootfs-artifacts' "$repo_dir/Makefile"
grep -Fqx $'\tpython3 -m scripts.runtime_artifact_bridge prepare' "$repo_dir/Makefile"
if grep -En 'glob\(|select\(|local_repository|new_local_repository|local_path_override|override_repository|os\.environ|tree_artifact' \
    "$repo_dir/image/runtime_artifacts.bzl" "$repo_dir/scripts/runtime_artifact_bridge.py"; then
    echo "runtime artifact bridge contains a forbidden generic mechanism" >&2
    exit 1
fi
if grep -En 'glob\(|select\(|load\(' "$repo_dir/build/runtime-artifacts/BUILD.bazel"; then
    echo "generated runtime artifact package is not exports-only" >&2
    exit 1
fi

mkdir "$temporary/clean"
cp -a "$repo_dir/.bazelrc" "$repo_dir/.bazelversion" "$repo_dir/BUILD.bazel" \
    "$repo_dir/MODULE.bazel" "$repo_dir/MODULE.bazel.lock" "$repo_dir/image" \
    "$repo_dir/scripts" "$temporary/clean/"
if (cd "$temporary/clean" && bazel --batch --output_base="$temporary/clean-output" build --symlink_prefix=/ \
    //image:runtime-artifact-members) >"$temporary/clean.log" 2>&1; then
    echo "clean Bazel build unexpectedly succeeded without explicit preparation" >&2
    exit 1
fi
grep -Fq '//build/runtime-artifacts' "$temporary/clean.log"
rm -rf -- "$temporary/clean-output"

for output in one two; do
    bazel --batch --output_base="$temporary/$output" build --symlink_prefix=/ //image:runtime-artifact-members
    bazel_bin=$(bazel --batch --output_base="$temporary/$output" info bazel-bin)
    cp "$bazel_bin/image/runtime-artifact-members.tar" "$temporary/$output.tar"
    cp "$bazel_bin/image/runtime-artifact-members.tsv" "$temporary/$output.tsv"
    rm -rf -- "${temporary:?}/$output"
done
cmp "$temporary/one.tar" "$temporary/two.tar"
cmp "$temporary/one.tsv" "$temporary/two.tsv"

mkdir "$temporary/drift"
cp -a "$repo_dir/.bazelrc" "$repo_dir/.bazelversion" "$repo_dir/BUILD.bazel" \
    "$repo_dir/MODULE.bazel" "$repo_dir/MODULE.bazel.lock" "$repo_dir/image" \
    "$repo_dir/scripts" "$temporary/drift/"
mkdir "$temporary/drift/build"
cp -a "$repo_dir/build/runtime-artifacts" "$temporary/drift/build/"
printf '# lock drift\n' >> "$temporary/drift/image/manifests/rootfs-artifacts.lock.tsv"
if (cd "$temporary/drift" && bazel --batch --output_base="$temporary/drift-output" build --symlink_prefix=/ \
    //image:runtime-artifact-members) >"$temporary/drift.log" 2>&1; then
    echo "Bazel bridge accepted a changed checked-in lock" >&2
    exit 1
fi
grep -Fq 'marker does not match' "$temporary/drift.log"
rm -rf -- "$temporary/drift-output"

mkdir "$temporary/mutation"
cp -a "$repo_dir/.bazelrc" "$repo_dir/.bazelversion" "$repo_dir/BUILD.bazel" \
    "$repo_dir/MODULE.bazel" "$repo_dir/MODULE.bazel.lock" "$repo_dir/image" \
    "$repo_dir/scripts" "$temporary/mutation/"
mkdir "$temporary/mutation/build"
cp -a "$repo_dir/build/runtime-artifacts" "$temporary/mutation/build/"
printf 'mutation' >> "$temporary/mutation/build/runtime-artifacts/producers/go/artifacts/tinfoil-init"
if (cd "$temporary/mutation" && bazel --batch --output_base="$temporary/mutation-output" build --symlink_prefix=/ \
    //image:runtime-artifact-members) >"$temporary/mutation.log" 2>&1; then
    echo "Bazel bridge accepted a generated artifact mutation" >&2
    exit 1
fi
grep -Fq 'differs from lock' "$temporary/mutation.log"
rm -rf -- "$temporary/mutation-output"
