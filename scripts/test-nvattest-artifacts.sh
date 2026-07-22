#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source "${repo_root}/scripts/nvattest-artifacts.sh"
readonly SO_VERSION=1.2.2
temporary="$(nvattest_make_owned_temp /tmp tinfoil-nvattest-test)"
cleanup() {
    sudo -n chown -R "$(id -u):$(id -g)" "${temporary}" 2>/dev/null || true
    nvattest_remove_owned_temp "${temporary}" /tmp tinfoil-nvattest-test
}
trap cleanup EXIT

expect_failure() {
    if "$@" >/dev/null 2>&1; then
        echo "expected failure: $*" >&2
        exit 1
    fi
}

mkdir -p "${temporary}/source/usr/bin"
mkdir -p "${temporary}/source/usr/lib/x86_64-linux-gnu"
install -m 0755 /bin/true "${temporary}/source/usr/bin/nvattest"
install -m 0644 /bin/true \
    "${temporary}/source/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"

ln -s "${temporary}/elsewhere" "${temporary}/symlink-output"
expect_failure nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/symlink-output" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)" 0

mkdir -p "${temporary}/unexpected-output"
touch "${temporary}/unexpected-output/unexpected"
expect_failure nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/unexpected-output" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)" 0
test -f "${temporary}/unexpected-output/unexpected"

mkdir -p "${temporary}/real-parent"
ln -s "${temporary}/real-parent" "${temporary}/linked-parent"
expect_failure nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/linked-parent/runtime" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)" 0
test ! -e "${temporary}/real-parent/runtime"

mkdir -p "${temporary}/dot-parent"
expect_failure nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/dot-parent/./runtime" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)" 0
test ! -e "${temporary}/dot-parent/runtime"

mkdir -p "${temporary}/dotdot-parent"
expect_failure nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/dotdot-parent/../escaped-runtime" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)" 0
test ! -e "${temporary}/escaped-runtime"

mkdir -p "${temporary}/fake-bin"
cat > "${temporary}/fake-bin/grep" <<EOF
#!/bin/bash
: > "${temporary}/dependency-check-ran"
exit 0
EOF
chmod +x "${temporary}/fake-bin/grep"
if (
    PATH="${temporary}/fake-bin"
    nvattest_verify_runtime_artifacts "${temporary}/source" "${SO_VERSION}"
) 2>/dev/null; then
    echo "verification unexpectedly succeeded without readelf" >&2
    exit 1
fi
test ! -e "${temporary}/dependency-check-ran"

mkdir -p "${temporary}/published"
nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/published" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)" 0
test -x "${temporary}/published/usr/bin/nvattest"
test -f "${temporary}/published/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"
test "$(stat -c %Y "${temporary}/published")" = 0

install -m 0755 /bin/false "${temporary}/source/usr/bin/nvattest"
nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/published" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)" 0
cmp /bin/false "${temporary}/published/usr/bin/nvattest"

foreign_uid=$(( $(id -u) + 1 ))
mkdir -p "${temporary}/foreign-output"
: > "${temporary}/foreign-output/untouched"
expect_failure nvattest_publish_runtime_artifacts \
    "${temporary}/source" "${temporary}/foreign-output" "${SO_VERSION}" \
    "${foreign_uid}" "$(id -g)" 0
test -f "${temporary}/foreign-output/untouched"
test "$(stat -c %u "${temporary}/foreign-output")" = "$(id -u)"

sudo -n true
published_library="${temporary}/published/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"
published_library_sha256="$(sha256sum "${published_library}")"
if [ "$(id -u)" = 0 ]; then
    foreign_uid=65534
else
    foreign_uid=0
fi
mkdir -p "${temporary}/foreign-owned-output"
: > "${temporary}/foreign-owned-output/untouched"
sudo -n chown -R "${foreign_uid}" "${temporary}/foreign-owned-output"
expect_failure sudo -n /bin/bash -c \
    'source "$1"; nvattest_publish_runtime_artifacts "$2" "$3" "$4" "$5" "$6" 0' \
    bash "${repo_root}/scripts/nvattest-artifacts.sh" \
    "${temporary}/source" "${temporary}/foreign-owned-output" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)"
test "$(stat -c %u "${temporary}/foreign-owned-output")" = "${foreign_uid}"
test -f "${temporary}/foreign-owned-output/untouched"
sudo -n chown -R "$(id -u):$(id -g)" "${temporary}/foreign-owned-output"

sudo -n chown "${foreign_uid}" "${published_library}"
expect_failure sudo -n /bin/bash -c \
    'source "$1"; nvattest_publish_runtime_artifacts "$2" "$3" "$4" "$5" "$6" 0' \
    bash "${repo_root}/scripts/nvattest-artifacts.sh" \
    "${temporary}/source" "${temporary}/published" "${SO_VERSION}" \
    "$(id -u)" "$(id -g)"
test "$(stat -c %u "${published_library}")" = "${foreign_uid}"
test "$(sha256sum "${published_library}")" = "${published_library_sha256}"
test -f "${temporary}/published/.stamp"
sudo -n chown "$(id -u):$(id -g)" "${published_library}"

mkdir -p "${temporary}/unowned"
expect_failure nvattest_remove_owned_temp \
    "${temporary}/unowned" "${temporary}" nested
test -d "${temporary}/unowned"

fixed="$(nvattest_make_fixed_owned_temp "${temporary}" fixed-build)"
test "${fixed}" = "${temporary}/fixed-build"
expect_failure nvattest_make_fixed_owned_temp "${temporary}" fixed-build
nvattest_remove_fixed_owned_temp "${fixed}" "${temporary}" fixed-build
test ! -e "${fixed}"

ln -s "${temporary}/elsewhere" "${temporary}/fixed-link"
expect_failure nvattest_make_fixed_owned_temp "${temporary}" fixed-link

echo "nvattest artifact path safety tests passed"
