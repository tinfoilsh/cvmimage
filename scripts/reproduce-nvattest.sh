#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "${repo_dir}/scripts/nvattest-artifacts.sh"

publish_cache=
if [ "$#" -gt 0 ]; then
    if [ "$#" -ne 2 ] || [ "$1" != "--publish-cache" ] || [ -z "$2" ]; then
        echo "usage: $0 [--publish-cache CACHE_ROOT]" >&2
        exit 2
    fi
    publish_cache=$2
fi

temporary="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-nvattest-repro.XXXXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT

"$repo_dir/scripts/build-runtime-builder.sh"

build_one() {
    local name=$1
    mkdir -p "$temporary/$name/packages" "$temporary/$name/runtime"
    TINFOIL_NVATTEST_DEB_OUTPUT="$temporary/$name/packages" \
        TINFOIL_NVATTEST_RUNTIME_OUTPUT="$temporary/$name/runtime" \
        TINFOIL_RUNTIME_BUILDER_CACHE="$temporary/$name/cache" \
        "$repo_dir/scripts/run-runtime-builder.sh" nvattest
}

build_one one
build_one two

for path in usr/bin/nvattest usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2; do
    first="$temporary/one/runtime/$path"
    second="$temporary/two/runtime/$path"
    cmp "$first" "$second"
    sha256sum "$first"
done

if [ -n "${publish_cache}" ]; then
    nvattest_publish_content_addressed_runtime_artifacts \
        "${temporary}/one/runtime" "${publish_cache}" \
        "${NVATTEST_RUNTIME_SO_VERSION}" \
        "${NVATTEST_RUNTIME_BINARY_SHA256}" \
        "${NVATTEST_RUNTIME_LIBRARY_SHA256}"
    echo "published verified nvattest runtime artifacts to ${publish_cache}"
fi

echo "nvattest runtime artifacts are byte-identical across isolated builds"
