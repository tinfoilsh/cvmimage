#!/usr/bin/env bash

select_tinfoil_kernel_profile() {
    local requested_profile="${TINFOIL_KERNEL_PROFILE:-release}"
    local default_build_root default_out_dir

    case "$requested_profile" in
        release)
            kernel_profile=release
            kernel_profile_fragment="$kernel_dir/profiles/release.config"
            kernel_expected_release=7.0.0-28-generic
            default_build_root="$kernel_dir/build"
            default_out_dir="$kernel_dir/out"
            ;;
        qualification-ibt)
            kernel_profile=qualification-ibt
            kernel_profile_fragment="$kernel_dir/profiles/qualification-ibt.config"
            kernel_expected_release=7.0.0-28-tinfoil-qualification-ibt
            default_build_root="$kernel_dir/build/qualification-ibt"
            default_out_dir="$kernel_dir/out/qualification-ibt"
            ;;
        debug)
            kernel_profile=debug
            kernel_profile_fragment="$kernel_dir/profiles/debug.config"
            kernel_expected_release=7.0.0-28-tinfoil-debug
            default_build_root="$kernel_dir/build/debug"
            default_out_dir="$kernel_dir/out/debug"
            ;;
        *)
            echo "unknown Tinfoil kernel profile: $requested_profile" >&2
            return 2
            ;;
    esac

    kernel_build_root="$(realpath -m -- "${TINFOIL_KERNEL_BUILD_ROOT:-$default_build_root}")"
    kernel_out_dir="$(realpath -m -- "${TINFOIL_KERNEL_OUT_DIR:-$default_out_dir}")"

    if [ -n "${TINFOIL_KERNEL_BUILD_ROOT:-}" ] &&
        [ "${kernel_build_root##*/}" != "$kernel_profile" ]; then
        echo "overridden kernel build root must end in /$kernel_profile" >&2
        return 2
    fi
    if [ -n "${TINFOIL_KERNEL_OUT_DIR:-}" ] &&
        [ "${kernel_out_dir##*/}" != "$kernel_profile" ]; then
        echo "overridden kernel output root must end in /$kernel_profile" >&2
        return 2
    fi
    if [ "$kernel_build_root" = "$kernel_out_dir" ]; then
        echo "kernel build and output roots must be distinct" >&2
        return 2
    fi

    if [ ! -f "$kernel_profile_fragment" ]; then
        echo "missing kernel profile fragment: $kernel_profile_fragment" >&2
        return 2
    fi
}

require_tinfoil_kernel_artifact_profile() {
    local artifact_profile_file=$1
    local artifact_release_file=$2
    local artifact_profile artifact_release

    if [ ! -f "$artifact_profile_file" ] || [ ! -f "$artifact_release_file" ]; then
        echo "missing kernel artifact identity" >&2
        return 1
    fi
    IFS= read -r artifact_profile < "$artifact_profile_file" || true
    IFS= read -r artifact_release < "$artifact_release_file" || true
    if [ "$artifact_profile" != "$kernel_profile" ] ||
        [ "$artifact_release" != "$kernel_expected_release" ]; then
        echo "kernel artifact identity mismatch" >&2
        return 1
    fi
}
