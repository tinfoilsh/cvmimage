#!/usr/bin/env bash

nvattest_require_tool() {
    local tool=$1
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "required tool is unavailable: ${tool}" >&2
        return 1
    }
}

nvattest_require_absolute_output() {
    local path=$1
    local component current=/
    local -a components
    if [[ "${path}" != /* || "${path}" = / ]]; then
        echo "output path must be an absolute non-root path: ${path}" >&2
        return 1
    fi
    IFS=/ read -r -a components <<<"${path#/}"
    for component in "${components[@]}"; do
        [ -n "${component}" ] || continue
        case "${component}" in
            .|..)
                echo "output path must not contain ${component} components: ${path}" >&2
                return 1
                ;;
        esac
        current="${current%/}/${component}"
        if [ -L "${current}" ]; then
            echo "output path must not traverse a symlink: ${current}" >&2
            return 1
        fi
    done
}

nvattest_make_owned_temp() {
    local parent=$1
    local prefix=$2
    local directory
    directory="$(mktemp -d -- "${parent%/}/${prefix}.XXXXXXXX")"
    : > "${directory}/.tinfoil-owned-temp"
    printf '%s\n' "${directory}"
}

nvattest_make_fixed_owned_temp() {
    local parent=$1
    local name=$2
    local directory="${parent%/}/${name}"

    [[ "${name}" =~ ^[a-z0-9-]+$ ]] || {
        echo "fixed temporary directory has invalid name: ${name}" >&2
        return 1
    }
    [ ! -e "${directory}" ] && [ ! -L "${directory}" ] || {
        echo "fixed temporary directory already exists: ${directory}" >&2
        return 1
    }
    mkdir -m 0700 -- "${directory}" || return
    : > "${directory}/.tinfoil-owned-temp" || return
    printf '%s\n' "${directory}"
}

nvattest_remove_owned_temp() {
    local directory=$1
    local parent=$2
    local prefix=$3
    local resolved_parent resolved_directory

    [ -n "${directory}" ] || return 0
    [ ! -L "${directory}" ] || {
        echo "refusing to clean symlinked temporary directory: ${directory}" >&2
        return 1
    }
    [ -f "${directory}/.tinfoil-owned-temp" ] || {
        echo "refusing to clean unowned temporary directory: ${directory}" >&2
        return 1
    }
    resolved_parent="$(realpath -e -- "${parent}")"
    resolved_directory="$(realpath -e -- "${directory}")"
    [[ "${resolved_directory}" = "${resolved_parent}/${prefix}."???????? ]] || {
        echo "refusing to clean unexpected temporary directory: ${resolved_directory}" >&2
        return 1
    }
    rm -rf --one-file-system -- "${resolved_directory}"
}

nvattest_remove_fixed_owned_temp() {
    local directory=$1
    local parent=$2
    local name=$3
    local resolved_parent resolved_directory

    [ -n "${directory}" ] || return 0
    [ ! -L "${directory}" ] || {
        echo "refusing to clean symlinked fixed temporary directory: ${directory}" >&2
        return 1
    }
    [ -f "${directory}/.tinfoil-owned-temp" ] &&
        [ ! -L "${directory}/.tinfoil-owned-temp" ] || {
        echo "refusing to clean unowned fixed temporary directory: ${directory}" >&2
        return 1
    }
    [ "$(stat -c %u -- "${directory}")" = "$(id -u)" ] || {
        echo "refusing to clean fixed temporary directory owned by another user: ${directory}" >&2
        return 1
    }
    resolved_parent="$(realpath -e -- "${parent}")"
    resolved_directory="$(realpath -e -- "${directory}")"
    [ "${resolved_directory}" = "${resolved_parent}/${name}" ] || {
        echo "refusing to clean unexpected fixed temporary directory: ${resolved_directory}" >&2
        return 1
    }
    rm -rf --one-file-system -- "${resolved_directory}"
}

nvattest_assert_runtime_shape() {
    local root=$1
    local so_version=$2
    local actual expected

    nvattest_require_tool find || return
    nvattest_require_tool sort || return
    actual="$(find "${root}" -mindepth 1 -printf '%y\t%P\n' | LC_ALL=C sort)"
    expected="$(printf '%s\t%s\n' \
        d usr \
        d usr/bin \
        d usr/lib \
        d usr/lib/x86_64-linux-gnu \
        f usr/bin/nvattest \
        f "usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}")"
    if [ "${actual}" != "${expected}" ]; then
        echo "unexpected nvattest runtime artifact tree:" >&2
        printf '%s\n' "${actual}" >&2
        return 1
    fi
}

nvattest_verify_runtime_artifacts() {
    local root=$1
    local so_version=$2
    local binary="${root}/usr/bin/nvattest"
    local library="${root}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"
    local binary_dynamic library_dynamic

    nvattest_require_tool readelf || return
    readelf --version >/dev/null || return
    nvattest_require_tool grep || return
    nvattest_assert_runtime_shape "${root}" "${so_version}" || return
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
}

nvattest_publish_runtime_artifacts() {
    local source=$1
    local destination=$2
    local so_version=$3
    local owner_uid=$4
    local owner_gid=$5
    local source_date_epoch=$6
    local destination_uid existing expected_library

    for tool in chown find install rm sort stat touch; do
        nvattest_require_tool "${tool}" || return
    done
    nvattest_require_absolute_output "${destination}" || return
    [[ "${owner_uid}" =~ ^[0-9]+$ && "${owner_gid}" =~ ^[0-9]+$ ]] || {
        echo "runtime artifact owner must be numeric" >&2
        return 1
    }
    if [ -e "${destination}" ]; then
        destination_uid="$(stat -c %u -- "${destination}")" || return
        [ "${destination_uid}" = "${owner_uid}" ] || {
            echo "refusing to replace runtime output directory owned by UID ${destination_uid}: ${destination}" >&2
            return 1
        }
        existing="$(find "${destination}" -mindepth 1 -printf '%y\t%U\t%P\n' | LC_ALL=C sort)" || return
        expected_library="f:usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"
        if [ -n "${existing}" ]; then
            while IFS=$'\t' read -r type uid path; do
                [ "${uid}" = "${owner_uid}" ] || {
                    echo "refusing to replace runtime output entry owned by UID ${uid}: ${path}" >&2
                    return 1
                }
                case "${type}:${path}" in
                    d:usr|d:usr/bin|d:usr/lib|d:usr/lib/x86_64-linux-gnu|f:.stamp|f:usr/bin/nvattest|"${expected_library}") ;;
                    *)
                        echo "refusing to replace unexpected runtime output entry: ${type} ${path}" >&2
                        return 1
                        ;;
                esac
            done <<<"${existing}"
        fi
    fi

    install -d -m 0755 \
        "${destination}/usr/bin" \
        "${destination}/usr/lib/x86_64-linux-gnu"
    rm -f -- "${destination}/.stamp"
    install -m 0755 "${source}/usr/bin/nvattest" \
        "${destination}/usr/bin/nvattest"
    install -m 0644 "${source}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}" \
        "${destination}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"
    find "${destination}" -depth -exec touch -h -d "@${source_date_epoch}" {} +
    touch -d "@${source_date_epoch}" "${destination}/.stamp"
    touch -d "@${source_date_epoch}" "${destination}"
    chown \
        "${owner_uid}:${owner_gid}" \
        "${destination}" \
        "${destination}/.stamp" \
        "${destination}/usr" \
        "${destination}/usr/bin" \
        "${destination}/usr/bin/nvattest" \
        "${destination}/usr/lib" \
        "${destination}/usr/lib/x86_64-linux-gnu" \
        "${destination}/usr/lib/x86_64-linux-gnu/libnvat.so.${so_version}"
}
