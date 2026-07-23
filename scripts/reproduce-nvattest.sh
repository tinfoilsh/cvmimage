#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
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

echo "nvattest runtime artifacts are byte-identical across isolated builds"
