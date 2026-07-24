#!/usr/bin/env bash

readonly NVATTEST_RUNTIME_SO_VERSION=1.2.2
readonly NVATTEST_RUNTIME_BINARY_SHA256=ef18d634cbcd9903baaedc6ed164af765175e88df3831f323c61ffe47c4109ed
readonly NVATTEST_RUNTIME_LIBRARY_SHA256=cbf70893dba2f554f8c218cb009705d09f62573db10b48994ffd8d66306c1e07

nvattest_require_tool() {
    local tool=$1
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "required tool is unavailable: ${tool}" >&2
        return 1
    }
}

nvattest_verify_sha256() {
    local path=$1
    local expected=$2
    local label=$3

    nvattest_require_tool sha256sum || return
    [ -f "${path}" ] || {
        echo "missing cached ${label}: ${path}" >&2
        return 1
    }
    if ! printf '%s  %s\n' "${expected}" "${path}" | \
        sha256sum --check --strict --status; then
        echo "cached ${label} SHA-256 mismatch" >&2
        return 1
    fi
}

nvattest_verify_runtime_artifacts() {
    local root=$1
    local so_version=$2
    local binary="${root}/usr/bin/nvattest"
    local library="${root}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"
    local binary_dynamic library_dynamic smoke_directory smoke_library_path

    nvattest_require_tool grep || return
    nvattest_require_tool readelf || return
    [ -x "${binary}" ] || {
        echo "nvattest runtime binary is missing or not executable" >&2
        return 1
    }
    [ -f "${library}" ] || {
        echo "libnvat runtime library is missing" >&2
        return 1
    }

    readelf -h "${binary}" >/dev/null || return
    readelf -h "${library}" >/dev/null || return
    binary_dynamic="$(readelf -d "${binary}")" || return
    library_dynamic="$(readelf -d "${library}")" || return
    grep -Fq 'Shared library: [libnvat.so.1]' <<<"${binary_dynamic}" || {
        echo "nvattest does not depend on libnvat.so.1" >&2
        return 1
    }
    grep -Fq 'Library soname: [libnvat.so.1]' <<<"${library_dynamic}" || {
        echo "libnvat does not expose the expected SONAME" >&2
        return 1
    }
    grep -Fq 'Shared library: [libxml2.so.16]' <<<"${library_dynamic}" || {
        echo "libnvat does not depend on libxml2.so.16" >&2
        return 1
    }
    if grep -Eq 'libxml2\.so\.2([^0-9]|$)' <<<"${library_dynamic}"; then
        echo "libnvat unexpectedly depends on libxml2.so.2" >&2
        return 1
    fi
    if grep -Eq '\((RPATH|RUNPATH)\)' <<<"${binary_dynamic}${library_dynamic}"; then
        echo "nvattest runtime artifacts must not contain RPATH or RUNPATH" >&2
        return 1
    fi

    if ! smoke_directory="$(mktemp -d)"; then
        echo "failed to create nvattest smoke-test directory" >&2
        return 1
    fi
    ln -s "${library}" "${smoke_directory}/libnvat.so.1"
    smoke_library_path="${smoke_directory}:${library%/*}"
    if [ -n "${LD_LIBRARY_PATH:-}" ]; then
        smoke_library_path="${smoke_library_path}:${LD_LIBRARY_PATH}"
    fi
    if ! LD_LIBRARY_PATH="${smoke_library_path}" \
        "${binary}" --help >/dev/null; then
        rm -rf -- "${smoke_directory}"
        echo "nvattest --help smoke test failed" >&2
        return 1
    fi
    rm -rf -- "${smoke_directory}"
}

nvattest_install_runtime_artifacts() {
    local source=$1
    local destination=$2
    local so_version=$3
    local owner_uid=$4
    local owner_gid=$5
    local source_date_epoch=$6
    local binary="${destination}/usr/bin/nvattest"
    local library="${destination}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"

    nvattest_verify_runtime_artifacts "${source}" "${so_version}" || return
    install -d -m 0755 -o "${owner_uid}" -g "${owner_gid}" \
        "${destination}" \
        "${destination}/usr" \
        "${destination}/usr/bin" \
        "${destination}/usr/lib" \
        "${destination}/usr/lib/x86_64-linux-gnu" || return
    install -m 0755 -o "${owner_uid}" -g "${owner_gid}" \
        "${source}/usr/bin/nvattest" "${binary}" || return
    install -m 0644 -o "${owner_uid}" -g "${owner_gid}" \
        "${source}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}" \
        "${library}" || return
    touch -h -d "@${source_date_epoch}" \
        "${binary}" \
        "${library}" \
        "${destination}/usr/lib/x86_64-linux-gnu" \
        "${destination}/usr/lib" \
        "${destination}/usr/bin" \
        "${destination}/usr" \
        "${destination}" || return
}

nvattest_publish_content_addressed_runtime_artifacts() {
    local source_root=$1
    local cache_root=$2
    local so_version=$3
    local binary_sha256=$4
    local library_sha256=$5
    local binary="${source_root}/usr/bin/nvattest"
    local library="${source_root}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"
    local binary_directory="${cache_root}/sha256/${binary_sha256}"
    local library_directory="${cache_root}/sha256/${library_sha256}"
    local binary_tmp="${binary_directory}/nvattest.tmp.$$"
    local library_tmp="${library_directory}/libnvat.so.${so_version}.tmp.$$"
    local binary_destination="${binary_directory}/nvattest"
    local library_destination="${library_directory}/libnvat.so.${so_version}"
    local binary_exists=0
    local library_exists=0
    local binary_published=0
    local library_published=0

    nvattest_verify_sha256 "${binary}" "${binary_sha256}" nvattest || return
    nvattest_verify_sha256 "${library}" "${library_sha256}" libnvat || return
    nvattest_verify_runtime_artifacts "${source_root}" "${so_version}" || return

    mkdir -p "${binary_directory}" "${library_directory}" || return
    if [ -e "${binary_destination}" ] || [ -L "${binary_destination}" ]; then
        if [ ! -f "${binary_destination}" ] || [ -L "${binary_destination}" ]; then
            echo "cached nvattest destination is not a regular file" >&2
            return 1
        fi
        nvattest_verify_sha256 \
            "${binary_destination}" "${binary_sha256}" nvattest || return
        binary_exists=1
    fi
    if [ -e "${library_destination}" ] || [ -L "${library_destination}" ]; then
        if [ ! -f "${library_destination}" ] || [ -L "${library_destination}" ]; then
            echo "cached libnvat destination is not a regular file" >&2
            return 1
        fi
        nvattest_verify_sha256 \
            "${library_destination}" "${library_sha256}" libnvat || return
        library_exists=1
    fi

    rm -f -- "${binary_tmp}" "${library_tmp}"
    install -m 0755 "${binary}" "${binary_tmp}" || return
    if ! install -m 0644 "${library}" "${library_tmp}"; then
        rm -f -- "${binary_tmp}" "${library_tmp}"
        return 1
    fi
    if ! nvattest_verify_sha256 "${binary_tmp}" "${binary_sha256}" nvattest || \
        ! nvattest_verify_sha256 "${library_tmp}" "${library_sha256}" libnvat; then
        rm -f -- "${binary_tmp}" "${library_tmp}"
        return 1
    fi

    if [ "${binary_exists}" -eq 0 ]; then
        if ! mv -fT "${binary_tmp}" "${binary_destination}"; then
            rm -f -- "${binary_tmp}" "${library_tmp}"
            return 1
        fi
        binary_published=1
    else
        rm -f -- "${binary_tmp}"
    fi
    if [ "${library_exists}" -eq 0 ]; then
        if ! mv -fT "${library_tmp}" "${library_destination}"; then
            if [ "${binary_published}" -eq 1 ]; then
                rm -f -- "${binary_destination}"
            fi
            rm -f -- "${library_tmp}"
            return 1
        fi
        library_published=1
    else
        rm -f -- "${library_tmp}"
    fi

    if ! nvattest_verify_sha256 \
        "${binary_destination}" "${binary_sha256}" nvattest || \
        ! nvattest_verify_sha256 \
            "${library_destination}" "${library_sha256}" libnvat; then
        if [ "${binary_published}" -eq 1 ]; then
            rm -f -- "${binary_destination}"
        fi
        if [ "${library_published}" -eq 1 ]; then
            rm -f -- "${library_destination}"
        fi
        return 1
    fi
}

nvattest_stage_content_addressed_runtime_artifacts() {
    local cache_root=$1
    local destination=$2
    local so_version=$3
    local binary_sha256=$4
    local library_sha256=$5
    local owner_uid=$6
    local owner_gid=$7
    local source_date_epoch=$8
    local binary_cache="${cache_root}/sha256/${binary_sha256}/nvattest"
    local library_cache="${cache_root}/sha256/${library_sha256}/libnvat.so.${so_version}"
    local source
    local result

    if ! source="$(mktemp -d)"; then
        echo "failed to create nvattest cache verification directory" >&2
        return 1
    fi
    mkdir -p "${source}/usr/bin" "${source}/usr/lib/x86_64-linux-gnu" || {
        rm -rf -- "${source}"
        return 1
    }
    [ -f "${binary_cache}" ] || {
        echo "missing cached nvattest: ${binary_cache}" >&2
        rm -rf -- "${source}"
        return 1
    }
    [ -f "${library_cache}" ] || {
        echo "missing cached libnvat: ${library_cache}" >&2
        rm -rf -- "${source}"
        return 1
    }
    install -m 0755 "${binary_cache}" "${source}/usr/bin/nvattest" || {
        rm -rf -- "${source}"
        return 1
    }
    install -m 0644 "${library_cache}" \
        "${source}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}" || {
        rm -rf -- "${source}"
        return 1
    }
    nvattest_verify_sha256 \
        "${source}/usr/bin/nvattest" "${binary_sha256}" nvattest || {
        rm -rf -- "${source}"
        return 1
    }
    nvattest_verify_sha256 \
        "${source}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}" \
        "${library_sha256}" libnvat || {
        rm -rf -- "${source}"
        return 1
    }
    if nvattest_install_runtime_artifacts \
        "${source}" "${destination}" "${so_version}" \
        "${owner_uid}" "${owner_gid}" "${source_date_epoch}"; then
        result=0
    else
        result=$?
    fi
    rm -rf -- "${source}"
    return "${result}"
}
