#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source "${repo_root}/scripts/nvattest-artifacts.sh"
readonly SO_VERSION="${NVATTEST_RUNTIME_SO_VERSION}"

nvattest_require_tool cc

temporary="$(mktemp -d)"
cleanup() {
    rm -rf -- "${temporary}"
}
trap cleanup EXIT

fixture="${temporary}/fixture"
mkdir -p "${fixture}/usr/bin" "${fixture}/usr/lib/x86_64-linux-gnu"

cat >"${temporary}/xml.c" <<'EOF'
int xml_marker(void) { return 0; }
EOF
cc -shared -fPIC -Wl,-soname,libxml2.so.16 \
    -o "${fixture}/usr/lib/x86_64-linux-gnu/libxml2.so.16" \
    "${temporary}/xml.c"
ln -s libxml2.so.16 "${fixture}/usr/lib/x86_64-linux-gnu/libxml2.so"

cat >"${temporary}/nvat.c" <<'EOF'
int nvat_marker(void) { return 0; }
EOF
cc -shared -fPIC -Wl,-soname,libnvat.so.1 \
    -L"${fixture}/usr/lib/x86_64-linux-gnu" \
    -Wl,-rpath-link,"${fixture}/usr/lib/x86_64-linux-gnu" \
    -o "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${temporary}/nvat.c" -Wl,--no-as-needed -lxml2
ln -s "libnvat.so.${SO_VERSION}" "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so"

cat >"${temporary}/nvattest.c" <<'EOF'
#include <string.h>
extern int nvat_marker(void);
int main(int argc, char **argv) {
    return argc == 2 && strcmp(argv[1], "--help") == 0 ? nvat_marker() : 2;
}
EOF
cc -L"${fixture}/usr/lib/x86_64-linux-gnu" \
    -Wl,-rpath-link,"${fixture}/usr/lib/x86_64-linux-gnu" \
    -o "${fixture}/usr/bin/nvattest" "${temporary}/nvattest.c" -lnvat

nvattest_verify_runtime_artifacts "${fixture}" "${SO_VERSION}"

binary_sha256="$(sha256sum "${fixture}/usr/bin/nvattest")"
binary_sha256="${binary_sha256%% *}"
library_sha256="$(sha256sum "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}")"
library_sha256="${library_sha256%% *}"
cache="${temporary}/cache"
mkdir -p \
    "${cache}/sha256/${binary_sha256}" \
    "${cache}/sha256/${library_sha256}"
cp "${fixture}/usr/bin/nvattest" \
    "${cache}/sha256/${binary_sha256}/nvattest"
cp "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${cache}/sha256/${library_sha256}/libnvat.so.${SO_VERSION}"

cached_output="${temporary}/cached-output"
nvattest_stage_content_addressed_runtime_artifacts \
    "${cache}" "${cached_output}" "${SO_VERSION}" \
    "${binary_sha256}" "${library_sha256}" "$(id -u)" "$(id -g)" 0
cmp "${fixture}/usr/bin/nvattest" "${cached_output}/usr/bin/nvattest"
cmp "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${cached_output}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"

published_cache="${temporary}/published-cache"
nvattest_publish_content_addressed_runtime_artifacts \
    "${fixture}" "${published_cache}" "${SO_VERSION}" \
    "${binary_sha256}" "${library_sha256}"
cmp "${fixture}/usr/bin/nvattest" \
    "${published_cache}/sha256/${binary_sha256}/nvattest"
cmp "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${published_cache}/sha256/${library_sha256}/libnvat.so.${SO_VERSION}"

rm "${cache}/sha256/${binary_sha256}/nvattest"
if nvattest_stage_content_addressed_runtime_artifacts \
    "${cache}" "${temporary}/missing-output" "${SO_VERSION}" \
    "${binary_sha256}" "${library_sha256}" "$(id -u)" "$(id -g)" 0 \
    2>"${temporary}/missing.log"; then
    echo "cache staging accepted a missing nvattest binary" >&2
    exit 1
fi
grep -Fq 'missing cached nvattest' "${temporary}/missing.log"

printf 'mismatch\n' >"${cache}/sha256/${binary_sha256}/nvattest"
if nvattest_stage_content_addressed_runtime_artifacts \
    "${cache}" "${temporary}/mismatch-output" "${SO_VERSION}" \
    "${binary_sha256}" "${library_sha256}" "$(id -u)" "$(id -g)" 0 \
    2>"${temporary}/mismatch.log"; then
    echo "cache staging accepted a mismatched nvattest binary" >&2
    exit 1
fi
grep -Fq 'cached nvattest SHA-256 mismatch' "${temporary}/mismatch.log"

output="${temporary}/output"
mkdir -p "${output}"
printf 'preserved\n' >"${output}/unrelated"
nvattest_install_runtime_artifacts \
    "${fixture}" "${output}" "${SO_VERSION}" "$(id -u)" "$(id -g)" 0

cmp "${fixture}/usr/bin/nvattest" "${output}/usr/bin/nvattest"
test -x "${output}/usr/bin/nvattest"
cmp \
    "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${output}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"
test -f "${output}/unrelated"
test "$(stat -c %Y "${output}/usr/bin/nvattest")" = 0
test "$(stat -c %Y "${output}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}")" = 0
for directory in \
    "${output}" \
    "${output}/usr" \
    "${output}/usr/bin" \
    "${output}/usr/lib" \
    "${output}/usr/lib/x86_64-linux-gnu"; do
    test "$(stat -c %Y "${directory}")" = 0
done

(
    mktemp() { return 1; }
    if nvattest_verify_runtime_artifacts "${fixture}" "${SO_VERSION}" \
        >"${temporary}/mktemp-failure.log" 2>&1; then
        echo "verification ignored mktemp failure" >&2
        exit 1
    fi
    grep -Fq 'failed to create nvattest smoke-test directory' \
        "${temporary}/mktemp-failure.log"
)

cc -shared -fPIC -Wl,-soname,libnvat.so.2 \
    -L"${fixture}/usr/lib/x86_64-linux-gnu" \
    -Wl,-rpath-link,"${fixture}/usr/lib/x86_64-linux-gnu" \
    -o "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${temporary}/nvat.c" -Wl,--no-as-needed -lxml2
if nvattest_verify_runtime_artifacts "${fixture}" "${SO_VERSION}" 2>/dev/null; then
    echo "verification accepted an incorrect libnvat SONAME" >&2
    exit 1
fi

cc -shared -fPIC -Wl,-soname,libnvat.so.1 \
    -L"${fixture}/usr/lib/x86_64-linux-gnu" \
    -Wl,-rpath-link,"${fixture}/usr/lib/x86_64-linux-gnu" \
    -o "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${temporary}/nvat.c" -Wl,--no-as-needed -lxml2
cat >"${temporary}/broken-nvattest.c" <<'EOF'
extern int nvat_marker(void);
int main(void) {
    return nvat_marker() == 0 ? 2 : 3;
}
EOF
cc -L"${fixture}/usr/lib/x86_64-linux-gnu" \
    -Wl,-rpath-link,"${fixture}/usr/lib/x86_64-linux-gnu" \
    -o "${fixture}/usr/bin/nvattest" "${temporary}/broken-nvattest.c" -lnvat
if nvattest_verify_runtime_artifacts "${fixture}" "${SO_VERSION}" 2>/dev/null; then
    echo "verification accepted a failing nvattest --help smoke test" >&2
    exit 1
fi

echo "nvattest named artifact tests passed"
