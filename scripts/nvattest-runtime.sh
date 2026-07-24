#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 stage | publish RUNTIME_ROOT" >&2
    exit 2
fi

readonly repo_root="$(git rev-parse --show-toplevel)"
readonly lock_file="${TINFOIL_NVATTEST_LOCK:-${repo_root}/image/nvattest-runtime.sha256}"
readonly cache_root="${TINFOIL_NVATTEST_CACHE:-${repo_root}/build/artifact-cache/sha256}"
readonly stage_root="${TINFOIL_NVATTEST_STAGE:-${repo_root}/build/rootfs-artifacts/nvattest}"
readonly nvattest_so_version=1.2.2
source "${repo_root}/scripts/nvattest-artifacts.sh"

read_lock() {
    local first_digest first_name second_digest second_name extra

    {
        read -r first_digest first_name
        read -r second_digest second_name
        read -r extra || true
    } <"${lock_file}"

    [[ "${first_digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "${second_digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
    [ "${first_name}" = nvattest ] || return 1
    [ "${second_name}" = "libnvat.so.${nvattest_so_version}" ] || return 1
    [ -z "${extra:-}" ] || return 1

    NVATTEST_DIGEST=${first_digest}
    LIBNVAT_DIGEST=${second_digest}
}

verify_cache_file() {
    local digest=$1 path="${cache_root}/$1"

    [ -f "${path}" ] && [ ! -L "${path}" ] || {
        echo "missing nvattest cache object: ${path}" >&2
        echo "run 'make regenerate-nvattest' explicitly to restore it" >&2
        return 1
    }
    printf '%s  %s\n' "${digest}" "${path}" | sha256sum --check --strict - >/dev/null
}

stage_cache() (
    local temporary

    verify_cache_file "${NVATTEST_DIGEST}"
    verify_cache_file "${LIBNVAT_DIGEST}"
    mkdir -p "${stage_root%/*}"
    temporary="$(mktemp -d "${stage_root%/*}/.nvattest.XXXXXXXX")"
    trap 'rm -rf -- "${temporary}"' EXIT
    install -d -m 0755 "${temporary}/usr/bin" "${temporary}/usr/lib/x86_64-linux-gnu"
    install -m 0755 "${cache_root}/${NVATTEST_DIGEST}" "${temporary}/usr/bin/nvattest"
    install -m 0644 "${cache_root}/${LIBNVAT_DIGEST}" \
        "${temporary}/usr/lib/x86_64-linux-gnu/libnvat.so.${nvattest_so_version}"
    touch -h -d @0 \
        "${temporary}" "${temporary}/usr" "${temporary}/usr/bin" \
        "${temporary}/usr/lib" "${temporary}/usr/lib/x86_64-linux-gnu" \
        "${temporary}/usr/bin/nvattest" \
        "${temporary}/usr/lib/x86_64-linux-gnu/libnvat.so.${nvattest_so_version}"
    printf '%s  %s\n' "${NVATTEST_DIGEST}" "${temporary}/usr/bin/nvattest" \
        | sha256sum --check --strict - >/dev/null
    printf '%s  %s\n' "${LIBNVAT_DIGEST}" \
        "${temporary}/usr/lib/x86_64-linux-gnu/libnvat.so.${nvattest_so_version}" \
        | sha256sum --check --strict - >/dev/null
    rm -rf -- "${stage_root}"
    mv -- "${temporary}" "${stage_root}"
)

publish_file() (
    local source=$1 digest=$2 destination="${cache_root}/$2" temporary

    printf '%s  %s\n' "${digest}" "${source}" | sha256sum --check --strict - >/dev/null || {
        echo "generated nvattest artifact does not match ${lock_file}" >&2
        sha256sum "${source}" >&2
        return 1
    }
    mkdir -p "${cache_root}"
    if [ -e "${destination}" ]; then
        verify_cache_file "${digest}"
        return
    fi
    temporary="$(mktemp "${cache_root}/.${digest}.XXXXXXXX")"
    trap 'rm -f -- "${temporary}"' EXIT
    install -m 0444 "${source}" "${temporary}"
    mv -- "${temporary}" "${destination}"
)

read_lock || {
    echo "invalid fixed nvattest lock: ${lock_file}" >&2
    exit 1
}

case "$1" in
    stage)
        [ "$#" -eq 1 ] || exit 2
        stage_cache
        ;;
    publish)
        [ "$#" -eq 2 ] || exit 2
        nvattest_verify_runtime_artifacts "$2" "${nvattest_so_version}"
        publish_file "$2/usr/bin/nvattest" "${NVATTEST_DIGEST}"
        publish_file "$2/usr/lib/x86_64-linux-gnu/libnvat.so.${nvattest_so_version}" "${LIBNVAT_DIGEST}"
        stage_cache
        ;;
    *)
        echo "usage: $0 stage | publish RUNTIME_ROOT" >&2
        exit 2
        ;;
esac
