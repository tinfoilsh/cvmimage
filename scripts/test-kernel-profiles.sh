#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-kernel-profiles-test.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

source "$kernel_dir/profile.sh"

expect_failure() {
    local label=$1
    shift
    if ("$@") > "$scratch/failure.log" 2>&1; then
        echo "accepted $label" >&2
        exit 1
    fi
}

check_profile() {
    local profile=$1
    local expected_release=$2
    local expected_build=$3
    local expected_out=$4

    unset TINFOIL_KERNEL_BUILD_ROOT TINFOIL_KERNEL_OUT_DIR
    TINFOIL_KERNEL_PROFILE=$profile
    select_tinfoil_kernel_profile
    test "$kernel_profile" = "$profile"
    test "$kernel_expected_release" = "$expected_release"
    test "$kernel_build_root" = "$expected_build"
    test "$kernel_out_dir" = "$expected_out"
}

check_profile release 7.0.0-28-generic "$kernel_dir/build" "$kernel_dir/out"
check_profile qualification-ibt 7.0.0-28-tinfoil-qualification-ibt \
    "$kernel_dir/build/qualification-ibt" "$kernel_dir/out/qualification-ibt"
check_profile debug 7.0.0-28-tinfoil-debug \
    "$kernel_dir/build/debug" "$kernel_dir/out/debug"

expect_failure "an unknown kernel profile" bash -c \
    'set -Eeuo pipefail; kernel_dir=$1; TINFOIL_KERNEL_PROFILE=unknown; source "$kernel_dir/profile.sh"; select_tinfoil_kernel_profile' \
    bash "$kernel_dir"

ln -s "$kernel_dir" "$scratch/kernel-link"
for alias in \
    "$kernel_dir/out/." \
    "$kernel_dir/out/" \
    "$kernel_dir/build/../out" \
    "$scratch/kernel-link/out"; do
    expect_failure "qualification output alias $alias" env \
        TINFOIL_KERNEL_PROFILE=qualification-ibt \
        "TINFOIL_KERNEL_OUT_DIR=$alias" \
        bash -c 'set -Eeuo pipefail; kernel_dir=$1; source "$kernel_dir/profile.sh"; select_tinfoil_kernel_profile' \
        bash "$kernel_dir"
done
for alias in \
    "$kernel_dir/build/." \
    "$kernel_dir/build/" \
    "$kernel_dir/out/../build" \
    "$scratch/kernel-link/build"; do
    expect_failure "qualification build alias $alias" env \
        TINFOIL_KERNEL_PROFILE=qualification-ibt \
        "TINFOIL_KERNEL_BUILD_ROOT=$alias" \
        bash -c 'set -Eeuo pipefail; kernel_dir=$1; source "$kernel_dir/profile.sh"; select_tinfoil_kernel_profile' \
        bash "$kernel_dir"
done

grep -Fqx 'CONFIG_LOCALVERSION="-28-generic"' "$kernel_dir/profiles/release.config"
grep -Fqx '# CONFIG_X86_KERNEL_IBT is not set' "$kernel_dir/profiles/release.config"
grep -Fqx 'CONFIG_LOCALVERSION="-28-tinfoil-qualification-ibt"' "$kernel_dir/profiles/qualification-ibt.config"
grep -Fqx 'CONFIG_X86_KERNEL_IBT=y' "$kernel_dir/profiles/qualification-ibt.config"
grep -Fqx 'CONFIG_LOCALVERSION="-28-tinfoil-debug"' "$kernel_dir/profiles/debug.config"
grep -Fqx '# CONFIG_X86_KERNEL_IBT is not set' "$kernel_dir/profiles/debug.config"
! grep -Eq '^(# )?CONFIG_(LOCALVERSION|X86_KERNEL_IBT)' "$kernel_dir/config.d/10-tinfoil-cvm-policy.config"

cat > "$scratch/release.config" <<'EOF'
CONFIG_LOCALVERSION="-28-generic"
# CONFIG_LOCALVERSION_AUTO is not set
# CONFIG_X86_KERNEL_IBT is not set
EOF
"$kernel_dir/check-config.sh" "$scratch/release.config" "$kernel_dir/profiles/release.config"

cat > "$scratch/qualification.config" <<'EOF'
CONFIG_LOCALVERSION="-28-tinfoil-qualification-ibt"
# CONFIG_LOCALVERSION_AUTO is not set
CONFIG_X86_KERNEL_IBT=y
EOF
"$kernel_dir/check-config.sh" "$scratch/qualification.config" "$kernel_dir/profiles/qualification-ibt.config"
expect_failure "IBT in the release profile" \
    "$kernel_dir/check-config.sh" "$scratch/qualification.config" "$kernel_dir/profiles/release.config"

TINFOIL_KERNEL_PROFILE=qualification-ibt \
    expect_failure "qualification NVIDIA artifacts" "$kernel_dir/build-nvidia-open-local.sh"

echo "kernel profile contract tests passed"
