#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "usage: $0 CACHE_ROOT" >&2
    exit 2
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "${repo_dir}/scripts/nvattest-artifacts.sh"

cache_root=$1
temporary="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-nvattest-regenerate.XXXXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "${temporary}/packages" "${temporary}/runtime"

TINFOIL_NVATTEST_DEB_OUTPUT="${temporary}/packages" \
TINFOIL_NVATTEST_RUNTIME_OUTPUT="${temporary}/runtime" \
    "${repo_dir}/scripts/run-runtime-builder.sh" nvattest

nvattest_publish_content_addressed_runtime_artifacts \
    "${temporary}/runtime" "${cache_root}" "${NVATTEST_RUNTIME_SO_VERSION}" \
    "${NVATTEST_RUNTIME_BINARY_SHA256}" "${NVATTEST_RUNTIME_LIBRARY_SHA256}"

echo "published verified nvattest runtime artifacts to ${cache_root}"
