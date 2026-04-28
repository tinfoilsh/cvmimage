#!/usr/bin/env bash
# Builds nvattest + libnvat from upstream source into ./packages/ for mkosi.
#
# TEMPORARY: remove once nvattest lands in the cuda-ubuntu2604 apt repo. At
# that point delete this script, drop the "Build nvattest from source" step
# in .github/workflows/release.yml, and remove the `nvattest` target +
# build-deps in Makefile. The pin in mkosi.conf will resolve from apt.

set -Eeuo pipefail

# --- Pins ---------------------------------------------------------------------

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/NVIDIA/attestation-sdk.git}"
UPSTREAM_TAG="${UPSTREAM_TAG:-2026.03.02}"
UPSTREAM_COMMIT_SHA="${UPSTREAM_COMMIT_SHA:-0c1be386a8fbb8f2766a6a556d10df86f5fed9d3}"

# Same snapshot as the rest of the build (mkosi.sandbox/.../50snapshot,
# release.yml runner setup).
APT_SNAPSHOT_DATE="${APT_SNAPSHOT_DATE:-20260424T000000Z}"

# Transitive CMake FetchContent deps. We pre-clone each at the expected
# commit SHA *before* cmake runs and pass the result via
# FETCHCONTENT_SOURCE_DIR_<NAME>, so a moved upstream tag can never cause
# arbitrary configure-time code from a different commit to execute.
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
JSON_URL="https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz"
JSON_SHA256="42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa"

PKG_VERSION="${PKG_VERSION:-1.2.0.1772475102-1}"
SO_VERSION="${SO_VERSION:-1.2.0}"
ARCH="${ARCH:-amd64}"

# Single source of truth for build-time deps. Used both by the apt-install
# inside the container bootstrap and by the missing-tools error message.
APT_DEPS=(
    cmake clang g++ git make perl pkg-config rustc cargo
    libxml2-dev autoconf automake libtool patchelf dpkg-dev
    curl xz-utils tar binutils
)
TOOL_BINS=(cmake git make cargo rustc pkg-config dpkg-deb g++ perl patchelf)

# --- Paths --------------------------------------------------------------------

OUT_DIR="${OUT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/packages}"
WORK_DIR="$(mktemp -d -t nvattest-build.XXXXXX)"
BUILD_DIR="${WORK_DIR}/build"
INSTALL_DIR="${WORK_DIR}/install"
PREFETCH_DIR="${WORK_DIR}/prefetch"
trap 'rm -rf "${WORK_DIR}"' EXIT

mkdir -p "${OUT_DIR}" "${PREFETCH_DIR}"

log()   { printf '\033[1;34m[build-nvattest]\033[0m %s\n' "$*"; }
fail()  { echo "ERROR: $*" >&2; exit 1; }

# --- Helpers ------------------------------------------------------------------

missing_tools() {
    local missing=() t
    for t in "${TOOL_BINS[@]}"; do
        command -v "${t}" >/dev/null 2>&1 || missing+=("${t}")
    done
    pkg-config --exists libxml-2.0 2>/dev/null || missing+=(libxml2-dev)
    printf '%s\n' "${missing[@]}"
}

# Self-bootstrap the toolchain pinned to snapshot.ubuntu.com when invoked
# as root in a fresh ubuntu:26.04 container. No-op on a dev host that
# already has the deps.
ensure_build_deps() {
    local missing
    missing="$(missing_tools)"
    [[ -z "${missing}" ]] && return 0
    if [[ "$(id -u)" != "0" \
          || ! -e /etc/apt/sources.list.d/ubuntu.sources \
          || -n "${SKIP_APT_BOOTSTRAP:-}" ]]; then
        echo "ERROR: missing build dependencies: ${missing//$'\n'/ }" >&2
        echo "On Ubuntu 26.04: sudo apt-get install -y \\" >&2
        echo "    ${APT_DEPS[*]}" >&2
        exit 1
    fi

    log "Bootstrapping build deps from snapshot.ubuntu.com/${APT_SNAPSHOT_DATE}"

    # ca-certificates first so apt can do TLS to snapshot.ubuntu.com. End-to-end
    # integrity is enforced by GPG verification of InRelease either way.
    DEBIAN_FRONTEND=noninteractive apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates

    cat > /etc/apt/sources.list.d/ubuntu.sources <<EOF
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT_DATE}
Suites: resolute resolute-updates resolute-security
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Check-Valid-Until: no
EOF
    DEBIAN_FRONTEND=noninteractive apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        "${APT_DEPS[@]}"

    missing="$(missing_tools)"
    [[ -z "${missing}" ]] || fail "still missing tools after bootstrap: ${missing//$'\n'/ }"
}

# git-fetch a single commit into a fresh dir and verify it's exactly the
# expected SHA (catches moved tags / mirrors that ignore the request).
prefetch_dep() {
    local name="$1" url="$2" expected="$3" target="$4" actual
    git init -q "${target}"
    git -C "${target}" remote add origin "${url}"
    git -C "${target}" fetch --quiet --depth=1 origin "${expected}"
    git -C "${target}" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
    actual="$(git -C "${target}" rev-parse HEAD)"
    [[ "${actual}" = "${expected}" ]] || fail "${name} fetched ${actual}, expected ${expected}"
    printf "  %-12s OK  %s\n" "${name}" "${actual}"
}

# Build a Debian binary package from a staged usr/ tree.
#   $1 = staging dir (containing DEBIAN/ + payload)
#   $2 = Package name
#   $3 = Section
#   $4 = Depends string
#   $5 = One-line Description
make_deb() {
    local staging="$1" pkg="$2" section="$3" depends="$4" desc="$5"
    local size
    size=$(du -sk "${staging}/usr" | awk '{print $1}')
    cat > "${staging}/DEBIAN/control" <<EOF
Package: ${pkg}
Source: libnvat
Version: ${PKG_VERSION}
Architecture: ${ARCH}
Maintainer: tinfoil <noreply@tinfoil.sh>
Installed-Size: ${size}
Depends: ${depends}
Section: ${section}
Priority: optional
Description: ${desc}
 Built from ${UPSTREAM_URL}@${UPSTREAM_TAG} until cuda-ubuntu2604 ships nvattest.
EOF
    dpkg-deb --root-owner-group --build "${staging}" \
        "${OUT_DIR}/${pkg}_${PKG_VERSION}_${ARCH}.deb"
}

# --- Run ----------------------------------------------------------------------

log "Output directory: ${OUT_DIR}"
log "Work directory:   ${WORK_DIR}"
log "Upstream:         ${UPSTREAM_URL}@${UPSTREAM_TAG}"
log "Package version:  ${PKG_VERSION}"

ensure_build_deps

log "Cloning ${UPSTREAM_URL} @ ${UPSTREAM_TAG}"
git clone --depth=1 --branch "${UPSTREAM_TAG}" "${UPSTREAM_URL}" "${WORK_DIR}/src"
actual_sha="$(git -C "${WORK_DIR}/src" rev-parse HEAD)"
[[ "${actual_sha}" = "${UPSTREAM_COMMIT_SHA}" ]] \
    || fail "upstream tag ${UPSTREAM_TAG} resolved to ${actual_sha}, expected ${UPSTREAM_COMMIT_SHA}; tag may have been moved"
log "Verified upstream commit SHA: ${actual_sha}"

# libxml2 v2.14 changed xmlGetLastError() to return const xmlError*. Upstream
# tag still uses the pre-v2.14 mutable type and won't compile against
# resolute's libxml2-16 (v2.15).
sed -i 's/xmlErrorPtr xml_error = xmlGetLastError();/const xmlError* xml_error = xmlGetLastError();/' \
    "${WORK_DIR}/src/nv-attestation-sdk-cpp/src/rim.cpp"

log "Pre-fetching transitive deps with SHA verification…"
declare -a FETCHCONTENT_OVERRIDES=()
for name in "${!DEP_SHAS[@]}"; do
    target="${PREFETCH_DIR}/${name}"
    prefetch_dep "${name}" "${DEP_REPOS[${name}]}" "${DEP_SHAS[${name}]}" "${target}"
    upper="$(tr '[:lower:]' '[:upper:]' <<< "${name}")"
    FETCHCONTENT_OVERRIDES+=( "-DFETCHCONTENT_SOURCE_DIR_${upper}=${target}" )
done

# Pre-fetch + SHA-verify nlohmann/json and seed FetchContent's cache so cmake
# won't redownload.
log "Pre-verifying nlohmann/json tarball"
JSON_CACHE_DIR="${BUILD_DIR}/_deps/json-subbuild/json-populate-prefix/src"
mkdir -p "${JSON_CACHE_DIR}"
curl -fsSL "${JSON_URL}" -o "${JSON_CACHE_DIR}/json.tar.xz"
echo "${JSON_SHA256}  ${JSON_CACHE_DIR}/json.tar.xz" | sha256sum -c -

log "Configuring (cmake)…"
cmake \
    -S "${WORK_DIR}/src/nv-attestation-cli" \
    -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DFETCHCONTENT_QUIET=OFF \
    "${FETCHCONTENT_OVERRIDES[@]}"

log "Building…"
cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

log "Installing into staging tree…"
DESTDIR="${INSTALL_DIR}" cmake --install "${BUILD_DIR}"
DESTDIR="${INSTALL_DIR}" cmake --install "${BUILD_DIR}/nv-attestation-sdk-build"

# Belt-and-suspenders: fail closed if the build leaks the old libxml2 ABI.
objdump -p "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    | grep -q 'libxml2\.so\.2$' \
    && fail "built libnvat still NEEDED libxml2.so.2 (expected libxml2.so.16)"

# --- Package -----------------------------------------------------------------

LIBNVAT_DIR="${WORK_DIR}/deb-libnvat"
mkdir -p "${LIBNVAT_DIR}/DEBIAN" "${LIBNVAT_DIR}/usr/lib/x86_64-linux-gnu"
cp -a \
    "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so" \
    "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.1" \
    "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${LIBNVAT_DIR}/usr/lib/x86_64-linux-gnu/"
make_deb "${LIBNVAT_DIR}" libnvat libs \
    "libc6 (>= 2.34), libgcc-s1 (>= 3.0), libstdc++6 (>= 13), libxml2-16 (>= 2.14)" \
    "Runtime libraries for NVIDIA attestation SDK (built from source)"

NVATTEST_DIR="${WORK_DIR}/deb-nvattest"
mkdir -p "${NVATTEST_DIR}/DEBIAN" "${NVATTEST_DIR}/usr/bin"
cp -a "${INSTALL_DIR}/usr/bin/nvattest" "${NVATTEST_DIR}/usr/bin/"
make_deb "${NVATTEST_DIR}" nvattest devel \
    "libnvat (= ${PKG_VERSION}), libc6 (>= 2.34), libgcc-s1 (>= 3.0), libstdc++6 (>= 13)" \
    "NVIDIA Attestation SDK CLI (built from source)"

# When this script ran inside a container as root on a host bind mount,
# hand the produced .debs back to the invoking user. No-op otherwise.
if [[ -n "${HOST_UID:-}" && "$(id -u)" = "0" ]]; then
    chown -R "${HOST_UID}:${HOST_GID:-${HOST_UID}}" "${OUT_DIR}"
fi

log "Done."
ls -la "${OUT_DIR}"/{libnvat,nvattest}_*.deb
