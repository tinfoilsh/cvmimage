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

ln -s "$scratch" "$scratch/root-link"
for profile in release qualification-ibt debug; do
    for other_profile in release qualification-ibt debug; do
        [ "$other_profile" != "$profile" ] || continue
        for root in \
            "$scratch/$other_profile" \
            "$scratch/$other_profile/." \
            "$scratch/root-link/$other_profile"; do
            expect_failure "$profile output root $root" env \
                "TINFOIL_KERNEL_PROFILE=$profile" \
                "TINFOIL_KERNEL_OUT_DIR=$root" \
                bash -c 'set -Eeuo pipefail; kernel_dir=$1; source "$kernel_dir/profile.sh"; select_tinfoil_kernel_profile' \
                bash "$kernel_dir"
            expect_failure "$profile build root $root" env \
                "TINFOIL_KERNEL_PROFILE=$profile" \
                "TINFOIL_KERNEL_BUILD_ROOT=$root" \
                bash -c 'set -Eeuo pipefail; kernel_dir=$1; source "$kernel_dir/profile.sh"; select_tinfoil_kernel_profile' \
                bash "$kernel_dir"
        done
    done
    env \
        "TINFOIL_KERNEL_PROFILE=$profile" \
        "TINFOIL_KERNEL_BUILD_ROOT=$scratch/build/$profile" \
        "TINFOIL_KERNEL_OUT_DIR=$scratch/out/$profile" \
        bash -c 'set -Eeuo pipefail; kernel_dir=$1; source "$kernel_dir/profile.sh"; select_tinfoil_kernel_profile' \
        bash "$kernel_dir"
done

expect_failure "shared kernel roots" env \
    TINFOIL_KERNEL_PROFILE=debug \
    "TINFOIL_KERNEL_BUILD_ROOT=$scratch/shared/debug" \
    "TINFOIL_KERNEL_OUT_DIR=$scratch/shared/debug" \
    bash -c 'set -Eeuo pipefail; kernel_dir=$1; source "$kernel_dir/profile.sh"; select_tinfoil_kernel_profile' \
    bash "$kernel_dir"

kernel_profile=release
kernel_expected_release=7.0.0-28-generic
mkdir -p "$scratch/artifact"
printf '%s\n' release > "$scratch/artifact/profile"
printf '%s\n' 7.0.0-28-generic > "$scratch/artifact/kernel.release"
require_tinfoil_kernel_artifact_profile \
    "$scratch/artifact/profile" "$scratch/artifact/kernel.release"
printf '%s\n' debug > "$scratch/artifact/profile"
expect_failure "a debug artifact labeled as release" \
    require_tinfoil_kernel_artifact_profile \
    "$scratch/artifact/profile" "$scratch/artifact/kernel.release"
printf '%s\n' release > "$scratch/artifact/profile"
printf '%s\n' 7.0.0-28-tinfoil-debug > "$scratch/artifact/kernel.release"
expect_failure "a debug release labeled as release" \
    require_tinfoil_kernel_artifact_profile \
    "$scratch/artifact/profile" "$scratch/artifact/kernel.release"

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
