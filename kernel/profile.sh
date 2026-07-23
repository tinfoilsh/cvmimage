#!/usr/bin/env bash

select_tinfoil_kernel_profile() {
    local requested_profile="${TINFOIL_KERNEL_PROFILE:-release}"
    local default_build_root default_out_dir release_build_root release_out_dir

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

    release_build_root="$(realpath -m -- "$kernel_dir/build")"
    release_out_dir="$(realpath -m -- "$kernel_dir/out")"
    kernel_build_root="$(realpath -m -- "${TINFOIL_KERNEL_BUILD_ROOT:-$default_build_root}")"
    kernel_out_dir="$(realpath -m -- "${TINFOIL_KERNEL_OUT_DIR:-$default_out_dir}")"

    if [ "$kernel_profile" != release ]; then
        if [ "$kernel_build_root" = "$release_build_root" ] ||
            [ "$kernel_out_dir" = "$release_out_dir" ]; then
            echo "$kernel_profile artifacts may not use the release build or output root" >&2
            return 2
        fi
    fi

    if [ ! -f "$kernel_profile_fragment" ]; then
        echo "missing kernel profile fragment: $kernel_profile_fragment" >&2
        return 2
    fi
}
