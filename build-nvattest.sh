#!/usr/bin/env bash
# Builds nvattest + libnvat from upstream source into ./packages/ for mkosi.
#
# TEMPORARY: remove once nvattest lands in the cuda-ubuntu2604 apt repo. At
# that point delete this script, drop the "Build nvattest from source" step
# in .github/workflows/release.yml, and remove the `nvattest` target +
# build-deps in Makefile. The pin in mkosi.conf will resolve from apt.

set -Eeuo pipefail

# Top-level pin — verified after clone. Override via env if you intentionally
# change the upstream version.
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/NVIDIA/attestation-sdk.git}"
UPSTREAM_TAG="${UPSTREAM_TAG:-2026.03.02}"
UPSTREAM_COMMIT_SHA="${UPSTREAM_COMMIT_SHA:-0c1be386a8fbb8f2766a6a556d10df86f5fed9d3}"

# Same snapshot as the rest of the build (mkosi.sandbox/.../50snapshot,
# release.yml runner setup).
APT_SNAPSHOT_DATE="${APT_SNAPSHOT_DATE:-20260424T000000Z}"

# Transitive CMake FetchContent deps that upstream pins by tag — verified
# post-configure. Names match the lowercase identifier in upstream's
# FetchContent_Declare(<name> ...).
declare -rA EXPECTED_DEP_SHAS=(
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/packages}"
WORK_DIR="$(mktemp -d -t nvattest-build.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

mkdir -p "${OUT_DIR}"

log() { printf '\033[1;34m[build-nvattest]\033[0m %s\n' "$*"; }

log "Output directory: ${OUT_DIR}"
log "Work directory:   ${WORK_DIR}"
log "Upstream:         ${UPSTREAM_URL}@${UPSTREAM_TAG}"
log "Package version:  ${PKG_VERSION}"

need() { command -v "$1" >/dev/null 2>&1 || missing+=("$1"); }
recheck_deps() {
    missing=()
    need cmake; need git; need make; need cargo; need rustc; need pkg-config
    need dpkg-deb; need g++; need perl; need patchelf
}

recheck_deps
have_libxml2=true
pkg-config --exists libxml-2.0 2>/dev/null || have_libxml2=false

# Self-bootstrap when invoked as root in a fresh ubuntu:26.04 container.
# Pulls toolchain from snapshot.ubuntu.com so it's reproducible. On a dev
# host with deps already installed this block is skipped silently.
if [[ ( ${#missing[@]} -gt 0 || "${have_libxml2}" = false ) \
      && "$(id -u)" = "0" \
      && -e /etc/apt/sources.list.d/ubuntu.sources \
      && -z "${SKIP_APT_BOOTSTRAP:-}" ]]; then
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
        cmake clang g++ git make perl pkg-config rustc cargo \
        libxml2-dev autoconf automake libtool patchelf dpkg-dev \
        curl xz-utils tar binutils
    recheck_deps
    pkg-config --exists libxml-2.0 && have_libxml2=true
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: missing build dependencies: ${missing[*]}" >&2
    echo "On Ubuntu 26.04: sudo apt-get install -y \\" >&2
    echo "    cmake clang g++ git make perl pkg-config rustc cargo \\" >&2
    echo "    libxml2-dev autoconf automake libtool patchelf dpkg-dev" >&2
    exit 1
fi
if [[ "${have_libxml2}" = false ]]; then
    echo "ERROR: libxml2 development files not found (install libxml2-dev)" >&2
    exit 1
fi

log "Cloning ${UPSTREAM_URL} @ ${UPSTREAM_TAG}"
git clone --depth=1 --branch "${UPSTREAM_TAG}" "${UPSTREAM_URL}" "${WORK_DIR}/src"

actual_sha="$(git -C "${WORK_DIR}/src" rev-parse HEAD)"
if [[ "${actual_sha}" != "${UPSTREAM_COMMIT_SHA}" ]]; then
    echo "ERROR: upstream tag ${UPSTREAM_TAG} resolved to ${actual_sha}," >&2
    echo "       expected ${UPSTREAM_COMMIT_SHA}. Tag may have been moved;" >&2
    echo "       audit before updating UPSTREAM_COMMIT_SHA." >&2
    exit 1
fi
log "Verified upstream commit SHA: ${actual_sha}"

# libxml2 v2.14 changed xmlGetLastError() to return const xmlError*. Upstream
# tag still uses the pre-v2.14 mutable type and won't compile against
# resolute's libxml2-16 (v2.15).
sed -i 's/xmlErrorPtr xml_error = xmlGetLastError();/const xmlError* xml_error = xmlGetLastError();/' \
    "${WORK_DIR}/src/nv-attestation-sdk-cpp/src/rim.cpp"

# Pre-populate FetchContent's cache for nlohmann/json so cmake doesn't need
# to redownload (and so we control the bytes).
log "Pre-verifying nlohmann/json tarball"
JSON_CACHE_DIR="${WORK_DIR}/build/_deps/json-subbuild/json-populate-prefix/src"
mkdir -p "${JSON_CACHE_DIR}"
curl -fsSL "${JSON_URL}" -o "${JSON_CACHE_DIR}/json.tar.xz"
echo "${JSON_SHA256}  ${JSON_CACHE_DIR}/json.tar.xz" | sha256sum -c -

BUILD_DIR="${WORK_DIR}/build"
INSTALL_DIR="${WORK_DIR}/install"

log "Configuring (cmake)…"
cmake \
    -S "${WORK_DIR}/src/nv-attestation-cli" \
    -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DFETCHCONTENT_QUIET=OFF

log "Verifying transitive FetchContent SHAs…"
for name in "${!EXPECTED_DEP_SHAS[@]}"; do
    expected="${EXPECTED_DEP_SHAS[$name]}"
    src_dir="${BUILD_DIR}/_deps/${name}-src"
    if [[ ! -e "${src_dir}/.git" ]]; then
        src_dir="$(find "${BUILD_DIR}/_deps/" -maxdepth 3 -type d -name "${name}-src" -print -quit 2>/dev/null || true)"
    fi
    if [[ -z "${src_dir}" || ! -e "${src_dir}/.git" ]]; then
        echo "ERROR: could not locate FetchContent source dir for ${name}" >&2
        exit 1
    fi
    actual="$(git -C "${src_dir}" rev-parse HEAD)"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "ERROR: ${name} resolved to ${actual}, expected ${expected}. Upstream tag moved." >&2
        exit 1
    fi
    printf "  %-12s OK  %s\n" "${name}" "${actual}"
done

log "Building…"
cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

log "Installing into staging tree…"
DESTDIR="${INSTALL_DIR}" cmake --install "${BUILD_DIR}"
DESTDIR="${INSTALL_DIR}" cmake --install "${BUILD_DIR}/nv-attestation-sdk-build"

# Belt-and-suspenders: fail closed if the build leaks the old libxml2 ABI.
if objdump -p "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
        | grep -q 'libxml2\.so\.2$'; then
    echo "ERROR: built libnvat still NEEDED libxml2.so.2 (expected libxml2.so.16)" >&2
    exit 1
fi

# --- Package: libnvat
LIBNVAT_DEB_DIR="${WORK_DIR}/deb-libnvat"
mkdir -p "${LIBNVAT_DEB_DIR}/DEBIAN" "${LIBNVAT_DEB_DIR}/usr/lib/x86_64-linux-gnu"
cp -a \
    "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so" \
    "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.1" \
    "${INSTALL_DIR}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${LIBNVAT_DEB_DIR}/usr/lib/x86_64-linux-gnu/"

LIBNVAT_SIZE=$(du -sk "${LIBNVAT_DEB_DIR}/usr" | awk '{print $1}')
cat > "${LIBNVAT_DEB_DIR}/DEBIAN/control" <<EOF
Package: libnvat
Source: libnvat
Version: ${PKG_VERSION}
Architecture: ${ARCH}
Maintainer: tinfoil <noreply@tinfoil.sh>
Installed-Size: ${LIBNVAT_SIZE}
Depends: libc6 (>= 2.34), libgcc-s1 (>= 3.0), libstdc++6 (>= 13), libxml2-16 (>= 2.14)
Section: libs
Priority: optional
Description: Runtime libraries for NVIDIA attestation SDK (built from source)
 Built from ${UPSTREAM_URL}@${UPSTREAM_TAG} until cuda-ubuntu2604 ships nvattest.
EOF
dpkg-deb --root-owner-group --build "${LIBNVAT_DEB_DIR}" \
    "${OUT_DIR}/libnvat_${PKG_VERSION}_${ARCH}.deb"

# --- Package: nvattest
NVATTEST_DEB_DIR="${WORK_DIR}/deb-nvattest"
mkdir -p "${NVATTEST_DEB_DIR}/DEBIAN" "${NVATTEST_DEB_DIR}/usr/bin"
cp -a "${INSTALL_DIR}/usr/bin/nvattest" "${NVATTEST_DEB_DIR}/usr/bin/"

NVATTEST_SIZE=$(du -sk "${NVATTEST_DEB_DIR}/usr" | awk '{print $1}')
cat > "${NVATTEST_DEB_DIR}/DEBIAN/control" <<EOF
Package: nvattest
Source: libnvat
Version: ${PKG_VERSION}
Architecture: ${ARCH}
Maintainer: tinfoil <noreply@tinfoil.sh>
Installed-Size: ${NVATTEST_SIZE}
Depends: libnvat (= ${PKG_VERSION}), libc6 (>= 2.34), libgcc-s1 (>= 3.0), libstdc++6 (>= 13)
Section: devel
Priority: optional
Description: NVIDIA Attestation SDK CLI (built from source)
 Built from ${UPSTREAM_URL}@${UPSTREAM_TAG} until cuda-ubuntu2604 ships nvattest.
EOF
dpkg-deb --root-owner-group --build "${NVATTEST_DEB_DIR}" \
    "${OUT_DIR}/nvattest_${PKG_VERSION}_${ARCH}.deb"

log "Done."
ls -la "${OUT_DIR}"/{libnvat,nvattest}_*.deb
