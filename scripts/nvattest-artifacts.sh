#!/usr/bin/env bash

nvattest_require_tool() {
    local tool=$1
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "required tool is unavailable: ${tool}" >&2
        return 1
    }
}

nvattest_verify_runtime_artifacts() {
    local root=$1
    local so_version=$2
    local binary="${root}/usr/bin/nvattest"
    local library="${root}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"
    local binary_dynamic library_dynamic smoke_directory

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
    if ! LD_LIBRARY_PATH="${smoke_directory}:${library%/*}" \
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
