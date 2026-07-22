#!/bin/bash
set -euo pipefail

files=(image/rootfs.bzl scripts/rootfs_assembly.py)
for forbidden in 'rules_'"pkg" 'flat'"ten(" 'dedup'"licate" 'glob'"(" 'local_'"repository" \
    'new_local_'"repository" 'local_path_'"override" '--override_'"repository" 'get'"env("; do
    if grep -Fq -- "$forbidden" "${files[@]}"; then
        echo "forbidden assembly mechanism: $forbidden" >&2
        exit 1
    fi
done

grep -Fq 'name = "rootfs"' image/BUILD.bazel
grep -Fq '"_packages": attr.label_list' image/rootfs.bzl
grep -Fq '"_vendors": attr.label_list' image/rootfs.bzl
grep -Fq '"_runtime": attr.label' image/rootfs.bzl
if grep -Eq '^[[:space:]]*"(packages|vendors|runtime|configs|sources|destinations)"[[:space:]]*:' image/rootfs.bzl; then
    echo "assembly inputs must remain private and fixed" >&2
    exit 1
fi
