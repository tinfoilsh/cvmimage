#!/usr/bin/env bash
# Builds nvattest + libnvat into ./packages/ for mkosi. Always runs inside an
# ubuntu:26.04 container as root (see Makefile / release.yml).
# TEMPORARY: drop once nvattest lands in cuda-ubuntu2604 — see Makefile.

set -Eeuo pipefail

UPSTREAM_URL=https://github.com/NVIDIA/attestation-sdk.git
UPSTREAM_TAG=2026.03.02
UPSTREAM_SHA=0c1be386a8fbb8f2766a6a556d10df86f5fed9d3
APT_SNAPSHOT_DATE=20260424T000000Z

# Transitive CMake FetchContent deps. We pre-fetch each at the expected SHA
# *before* cmake runs and pass FETCHCONTENT_SOURCE_DIR_<NAME>, so a moved
# upstream tag can never cause arbitrary configure-time code to execute.
declare -rA DEP_REPOS=(
    [corrosion]=https://github.com/corrosion-rs/corrosion.git
    [regorus]=https://github.com/microsoft/regorus.git
    [jwt-cpp]=https://github.com/Thalhammer/jwt-cpp.git
    [fmt]=https://github.com/fmtlib/fmt.git
    [spdlog]=https://github.com/gabime/spdlog.git
)
declare -rA DEP_SHAS=(
    [corrosion]=6be991bb34c348dfb8344be22f3606288ea5c7fd
    [regorus]=c7bf460bc160c96e38048296e5708943d2e43909
    [jwt-cpp]=e71e0c2d584baff06925bbb3aad683f677e4d498
    [fmt]=e69e5f977d458f2650bb346dadf2ad30c5320281
    [spdlog]=27cb4c76708608465c413f6d0e6b8d99a4d84302
)

# Upstream fetches nlohmann/json by URL without URL_HASH; we verify it ourselves.
JSON_URL=https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
JSON_SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa

PKG_VERSION=1.2.0.1772475102-1
SO_VERSION=1.2.0
ARCH=amd64

OUT_DIR="$(cd "$(dirname "$0")" && pwd)/packages"
WORK="$(mktemp -d)"
SRC="${WORK}/src"
BUILD="${WORK}/build"
INSTALL="${WORK}/install"
mkdir -p "${OUT_DIR}"

# Bootstrap toolchain from snapshot.ubuntu.com (reproducible). ca-certificates
# first so apt can do TLS to snapshot; integrity is enforced by GPG either way.
# Drop docker-clean so /var/cache/apt/archives survives across container runs
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get update -q
apt-get install -y --no-install-recommends ca-certificates
cat > /etc/apt/sources.list.d/ubuntu.sources <<EOF
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT_DATE}
Suites: resolute resolute-updates resolute-security
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Check-Valid-Until: no
EOF
apt-get update -q
apt-get install -y --no-install-recommends \
    build-essential cmake git perl pkg-config rustc cargo \
    libxml2-dev curl xz-utils

# Clone upstream and verify SHA.
git clone --depth=1 --branch "${UPSTREAM_TAG}" "${UPSTREAM_URL}" "${SRC}"
[[ "$(git -C "${SRC}" rev-parse HEAD)" = "${UPSTREAM_SHA}" ]]

# libxml2 v2.14 changed xmlGetLastError() to return const xmlError*.
sed -i 's/xmlErrorPtr xml_error = xmlGetLastError();/const xmlError* xml_error = xmlGetLastError();/' \
    "${SRC}/nv-attestation-sdk-cpp/src/rim.cpp"

# Pre-fetch transitive deps at their expected SHA before cmake configures.
fetchcontent_overrides=()
for name in "${!DEP_SHAS[@]}"; do
    target="${WORK}/prefetch/${name}"
    git init -q "${target}"
    git -C "${target}" remote add origin "${DEP_REPOS[${name}]}"
    git -C "${target}" fetch --depth=1 origin "${DEP_SHAS[${name}]}"
    git -C "${target}" -c advice.detachedHead=false checkout FETCH_HEAD
    [[ "$(git -C "${target}" rev-parse HEAD)" = "${DEP_SHAS[${name}]}" ]]
    upper="$(tr '[:lower:]' '[:upper:]' <<< "${name}")"
    fetchcontent_overrides+=( "-DFETCHCONTENT_SOURCE_DIR_${upper}=${target}" )
done

# Pre-fetch + verify nlohmann/json into FetchContent's cache.
json_cache="${BUILD}/_deps/json-subbuild/json-populate-prefix/src"
mkdir -p "${json_cache}"
curl -fsSL "${JSON_URL}" -o "${json_cache}/json.tar.xz"
echo "${JSON_SHA256}  ${json_cache}/json.tar.xz" | sha256sum -c -

cmake -S "${SRC}/nv-attestation-cli" -B "${BUILD}" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=OFF -DBUILD_EXAMPLES=OFF \
    "${fetchcontent_overrides[@]}"
cmake --build "${BUILD}" --parallel "$(nproc)"
DESTDIR="${INSTALL}" cmake --install "${BUILD}"
DESTDIR="${INSTALL}" cmake --install "${BUILD}/nv-attestation-sdk-build"

make_deb() {
    local stage=$1 pkg=$2 section=$3 deps=$4 desc=$5
    local size; size=$(du -sk "${stage}/usr" | awk '{print $1}')
    cat > "${stage}/DEBIAN/control" <<EOF
Package: ${pkg}
Source: libnvat
Version: ${PKG_VERSION}
Architecture: ${ARCH}
Maintainer: tinfoil <noreply@tinfoil.sh>
Installed-Size: ${size}
Depends: ${deps}
Section: ${section}
Priority: optional
Description: ${desc}
 Built from ${UPSTREAM_URL}@${UPSTREAM_TAG}.
EOF
    dpkg-deb --root-owner-group --build "${stage}" \
        "${OUT_DIR}/${pkg}_${PKG_VERSION}_${ARCH}.deb"
}

libnvat="${WORK}/deb-libnvat"
mkdir -p "${libnvat}/DEBIAN" "${libnvat}/usr/lib/x86_64-linux-gnu"
cp -a "${INSTALL}"/usr/lib/x86_64-linux-gnu/libnvat.so{,.1,.${SO_VERSION}} \
    "${libnvat}/usr/lib/x86_64-linux-gnu/"
make_deb "${libnvat}" libnvat libs \
    "libc6 (>= 2.34), libgcc-s1 (>= 3.0), libstdc++6 (>= 13), libxml2-16 (>= 2.14)" \
    "Runtime libraries for NVIDIA attestation SDK (built from source)"

nvattest="${WORK}/deb-nvattest"
mkdir -p "${nvattest}/DEBIAN" "${nvattest}/usr/bin"
cp -a "${INSTALL}/usr/bin/nvattest" "${nvattest}/usr/bin/"
make_deb "${nvattest}" nvattest devel \
    "libnvat (= ${PKG_VERSION}), libc6 (>= 2.34), libgcc-s1 (>= 3.0), libstdc++6 (>= 13)" \
    "NVIDIA Attestation SDK CLI (built from source)"

chown -R "${HOST_UID}:${HOST_GID}" "${OUT_DIR}"
ls -la "${OUT_DIR}"/{libnvat,nvattest}_*.deb
