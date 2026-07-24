#!/usr/bin/env bash
# Builds the two named nvattest runtime artifacts used by the additive rootfs.
# Always runs inside the shared pinned runtime builder selected by the Makefile.
# The cuda-ubuntu2604 repo now ships nvattest, but its libnvat links
# libxml2.so.2 while Ubuntu resolute ships only libxml2.so.16 (libxml2 2.14
# bumped the SONAME). So we keep building from source against system libxml2-16.

set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

readonly UPSTREAM_URL=https://github.com/NVIDIA/attestation-sdk.git
readonly UPSTREAM_TAG=2026.06.09
readonly UPSTREAM_SHA=9d12801cea8a198ea0f29640dfaf8a4017c841c5

# Transitive CMake FetchContent deps. We pre-fetch each at the expected SHA
# *before* cmake runs and pass FETCHCONTENT_SOURCE_DIR_<NAME>, so a moved
# upstream tag can never cause arbitrary configure-time code to execute.
declare -rA DEP_REPOS=(
    [cli11]=https://github.com/CLIUtils/CLI11.git
    [corrosion]=https://github.com/corrosion-rs/corrosion.git
    [regorus]=https://github.com/microsoft/regorus.git
    [jwt-cpp]=https://github.com/Thalhammer/jwt-cpp.git
    [fmt]=https://github.com/fmtlib/fmt.git
    [spdlog]=https://github.com/gabime/spdlog.git
)
declare -rA DEP_SHAS=(
    [cli11]=bfffd37e1f804ca4fae1caae106935791696b6a9
    [corrosion]=6be991bb34c348dfb8344be22f3606288ea5c7fd
    [regorus]=c7bf460bc160c96e38048296e5708943d2e43909
    [jwt-cpp]=e71e0c2d584baff06925bbb3aad683f677e4d498
    [fmt]=e69e5f977d458f2650bb346dadf2ad30c5320281
    [spdlog]=27cb4c76708608465c413f6d0e6b8d99a4d84302
)

# Upstream fetches nlohmann/json by URL without URL_HASH; we verify it ourselves.
readonly JSON_URL=https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
readonly JSON_SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
readonly REGORUS_LOCK_SHA256=847ed5732480d7b4bdb65ed932c0413f6966c5bdc5a62e272be9a48bf103cd3b

readonly SO_VERSION=1.2.2

RUNTIME_OUT_DIR="${repo_dir}/build/rootfs-artifacts/nvattest"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime-output)
            RUNTIME_OUT_DIR=${2:?missing value for --runtime-output}
            shift 2
            ;;
        *)
            echo "usage: $0 [--runtime-output DIR]" >&2
            exit 2
            ;;
    esac
done

WORK=/tmp/tinfoil-nvattest-build
SRC="${WORK}/src"
BUILD="${WORK}/build"
INSTALL="${WORK}/install"
cleanup() {
    rm -rf -- "${WORK}"
}
trap cleanup EXIT

rm -rf -- "${WORK}"
mkdir -p "${WORK}"

export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C.UTF-8
prefix_map="-ffile-prefix-map=${WORK}=/usr/src/tinfoil-nvattest -fdebug-prefix-map=${WORK}=/usr/src/tinfoil-nvattest"
portable_target="-march=x86-64 -mtune=generic"
export CFLAGS="${prefix_map} ${portable_target}"
export CXXFLAGS="${prefix_map} ${portable_target}"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=${WORK}=/usr/src/tinfoil-nvattest -C target-cpu=x86-64 -C codegen-units=1"
export CARGO_BUILD_JOBS=1

# Clone upstream and verify SHA.
git clone --depth=1 --branch "${UPSTREAM_TAG}" "${UPSTREAM_URL}" "${SRC}"
[[ "$(git -C "${SRC}" rev-parse HEAD)" = "${UPSTREAM_SHA}" ]]

# Pre-fetch transitive deps at their expected SHA before cmake configures.
fetchcontent_overrides=()
mapfile -t dependency_names < <(printf '%s\n' "${!DEP_SHAS[@]}" | sort)
for name in "${dependency_names[@]}"; do
    target="${WORK}/prefetch/${name}"
    git init -q "${target}"
    git -C "${target}" remote add origin "${DEP_REPOS[${name}]}"
    git -C "${target}" fetch --depth=1 origin "${DEP_SHAS[${name}]}"
    git -C "${target}" -c advice.detachedHead=false checkout FETCH_HEAD
    [[ "$(git -C "${target}" rev-parse HEAD)" = "${DEP_SHAS[${name}]}" ]]
    upper="$(tr '[:lower:]' '[:upper:]' <<< "${name}")"
    fetchcontent_overrides+=( "-DFETCHCONTENT_SOURCE_DIR_${upper}=${target}" )
done

printf '%s  %s\n' \
    "${REGORUS_LOCK_SHA256}" \
    "${repo_dir}/scripts/nvattest-regorus-Cargo.lock" | sha256sum --check --strict -
install -m 0444 "${repo_dir}/scripts/nvattest-regorus-Cargo.lock" \
    "${WORK}/prefetch/regorus/bindings/ffi/Cargo.lock"
cargo fetch --locked \
    --manifest-path "${WORK}/prefetch/regorus/bindings/ffi/Cargo.toml"
export CARGO_NET_OFFLINE=true

# Pre-fetch + verify nlohmann/json into FetchContent's cache.
json_cache="${BUILD}/_deps/json-subbuild/json-populate-prefix/src"
mkdir -p "${json_cache}"
curl -fsSL "${JSON_URL}" -o "${json_cache}/json.tar.xz"
echo "${JSON_SHA256}  ${json_cache}/json.tar.xz" | sha256sum -c -

cmake -S "${SRC}/nv-attestation-cli" -B "${BUILD}" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_EXE_LINKER_FLAGS=-Wl,--build-id=none \
    -DCMAKE_SHARED_LINKER_FLAGS=-Wl,--build-id=none \
    -DBUILD_TESTING=OFF -DBUILD_EXAMPLES=OFF \
    "${fetchcontent_overrides[@]}"
cmake --build "${BUILD}" --parallel 1
DESTDIR="${INSTALL}" cmake --install "${BUILD}"
DESTDIR="${INSTALL}" cmake --install "${BUILD}/nv-attestation-sdk-build"

/usr/bin/strip --strip-unneeded \
    "${INSTALL}/usr/bin/nvattest" \
    "${INSTALL}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"

rm -rf -- "${RUNTIME_OUT_DIR}"
install -d -m 0755 \
    "${RUNTIME_OUT_DIR}/usr/bin" \
    "${RUNTIME_OUT_DIR}/usr/lib/x86_64-linux-gnu"
install -m 0755 "${INSTALL}/usr/bin/nvattest" \
    "${RUNTIME_OUT_DIR}/usr/bin/nvattest"
install -m 0644 "${INSTALL}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${RUNTIME_OUT_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"
touch -h -d "@${SOURCE_DATE_EPOCH}" \
    "${RUNTIME_OUT_DIR}/usr/bin/nvattest" \
    "${RUNTIME_OUT_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"

sha256sum \
    "${RUNTIME_OUT_DIR}/usr/bin/nvattest" \
    "${RUNTIME_OUT_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"
