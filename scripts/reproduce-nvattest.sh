#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source "${repo_root}/scripts/nvattest-artifacts.sh"
builder="$(<"${repo_root}/scripts/nvattest-builder-image.txt")"
temporary="$(nvattest_make_owned_temp /tmp tinfoil-nvattest-repro)"
cleanup() {
    nvattest_remove_owned_temp "${temporary}" /tmp tinfoil-nvattest-repro
}
trap cleanup EXIT

mkdir -p "${temporary}/one/packages" "${temporary}/one/runtime"
mkdir -p "${temporary}/two/packages" "${temporary}/two/runtime"

build_one() {
    local name=$1
    docker run --rm \
        --name "cvmimage-nvattest-repro-${name}-$$" \
        --mount "type=bind,src=${repo_root}/build-nvattest.sh,dst=/source/build-nvattest.sh,readonly" \
        --mount "type=bind,src=${repo_root}/scripts/nvattest-artifacts.sh,dst=/source/scripts/nvattest-artifacts.sh,readonly" \
        --mount "type=bind,src=${repo_root}/scripts/nvattest-regorus-Cargo.lock,dst=/source/scripts/nvattest-regorus-Cargo.lock,readonly" \
        --mount "type=bind,src=${temporary}/${name}/packages,dst=/output/packages" \
        --mount "type=bind,src=${temporary}/${name}/runtime,dst=/output/runtime" \
        -w /source \
        -e DEBIAN_FRONTEND=noninteractive \
        -e HOST_UID="$(id -u)" \
        -e HOST_GID="$(id -g)" \
        "${builder}" \
        bash ./build-nvattest.sh \
            --deb-output /output/packages \
            --runtime-output /output/runtime
}

build_one one
build_one two

for path in usr/bin/nvattest usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2; do
    first="${temporary}/one/runtime/${path}"
    second="${temporary}/two/runtime/${path}"
    cmp "${first}" "${second}"
    sha256sum "${first}"
done

echo "nvattest runtime artifacts are byte-identical across isolated builds"
