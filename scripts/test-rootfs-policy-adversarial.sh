#!/bin/bash
set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C

repo_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/rootfs-policy-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

fail() {
    echo "test-rootfs-policy-adversarial.sh: $*" >&2
    exit 1
}

copy_case() {
    local name=$1
    local case_dir="$scratch/$name"
    mkdir -p "$case_dir/scripts" "$case_dir/mkosi.extra/etc/containerd" ||
        fail "failed to create case directory: $name"
    cp -a "$repo_dir/image" "$case_dir/" || fail "failed to copy policy image: $name"
    cp -a "$repo_dir/mkosi.extra/etc/containerd/config.toml" \
        "$case_dir/mkosi.extra/etc/containerd/" ||
        fail "failed to copy installed containerd configuration: $name"
    cp -a "$repo_dir/scripts/test-rootfs-policy.sh" "$case_dir/scripts/" ||
        fail "failed to copy policy verifier: $name"
    printf '%s\n' "$case_dir"
}

expect_rejected() {
    local case_dir=$1
    if "$case_dir/scripts/test-rootfs-policy.sh" >"$scratch/stdout" 2>"$scratch/stderr"; then
        fail "mutation was accepted: $case_dir"
    fi
}

"$repo_dir/scripts/test-rootfs-policy.sh"

touch "$scratch/setup-failure"
if case_dir=$(copy_case setup-failure 2>"$scratch/setup-failure.stderr"); then
    fail "copy_case accepted a failed setup: $case_dir"
fi
if ! grep -Fxq 'test-rootfs-policy-adversarial.sh: failed to create case directory: setup-failure' \
    "$scratch/setup-failure.stderr"; then
    fail "copy_case did not report its setup failure"
fi

case_dir=$(copy_case extra-top-level)
printf 'unexpected\n' >"$case_dir/image/rootfs/unexpected"
expect_rejected "$case_dir"

case_dir=$(copy_case extra-nested)
mkdir -p "$case_dir/image/rootfs/etc/unexpected/deeper"
expect_rejected "$case_dir"

case_dir=$(copy_case root-mode)
chmod 0700 "$case_dir/image/rootfs"
expect_rejected "$case_dir"

case_dir=$(copy_case root-xattr)
if python3 - "$case_dir/image/rootfs" <<'PY'
import os
import sys

try:
    os.setxattr(sys.argv[1], "user.policy-test", b"unexpected", follow_symlinks=False)
except OSError:
    raise SystemExit(1)
PY
then
    expect_rejected "$case_dir"
fi

case_dir=$(copy_case file-xattr)
if python3 - "$case_dir/image/rootfs/etc/hosts" <<'PY'
import os
import sys

try:
    os.setxattr(sys.argv[1], "user.policy-test", b"unexpected", follow_symlinks=False)
except OSError:
    raise SystemExit(1)
PY
then
    expect_rejected "$case_dir"
fi

case_dir=$(copy_case symlink)
rm "$case_dir/image/rootfs/etc/hosts"
ln -s hostname "$case_dir/image/rootfs/etc/hosts"
expect_rejected "$case_dir"

case_dir=$(copy_case installed-containerd-mismatch)
printf '\n# unexpected\n' >>"$case_dir/mkosi.extra/etc/containerd/config.toml"
expect_rejected "$case_dir"

case_dir=$(copy_case installed-containerd-symlink)
rm "$case_dir/mkosi.extra/etc/containerd/config.toml"
ln -s ../../../image/rootfs/etc/containerd/config.toml \
    "$case_dir/mkosi.extra/etc/containerd/config.toml"
expect_rejected "$case_dir"
