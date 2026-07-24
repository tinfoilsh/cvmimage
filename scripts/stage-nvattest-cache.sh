#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
    echo "usage: $0 CACHE_ROOT RUNTIME_OUTPUT" >&2
    exit 2
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "${repo_dir}/scripts/nvattest-artifacts.sh"
readonly NVATTEST_SOURCE_DATE_EPOCH=0

nvattest_stage_content_addressed_runtime_artifacts \
    "$1" "$2" "${NVATTEST_RUNTIME_SO_VERSION}" \
    "${NVATTEST_RUNTIME_BINARY_SHA256}" "${NVATTEST_RUNTIME_LIBRARY_SHA256}" \
    "$(id -u)" "$(id -g)" "${NVATTEST_SOURCE_DATE_EPOCH}"
