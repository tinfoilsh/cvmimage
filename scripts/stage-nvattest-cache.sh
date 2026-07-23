#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 CACHE_ROOT RUNTIME_OUTPUT" >&2
    exit 2
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "${repo_dir}/scripts/nvattest-artifacts.sh"

nvattest_stage_content_addressed_runtime_artifacts \
    "$1" "$2" "${NVATTEST_RUNTIME_SO_VERSION}" \
    "${NVATTEST_RUNTIME_BINARY_SHA256}" "${NVATTEST_RUNTIME_LIBRARY_SHA256}" \
    "$(id -u)" "$(id -g)" 0
