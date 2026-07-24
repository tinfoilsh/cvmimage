#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source "${repo_root}/scripts/nvattest-artifacts.sh"
readonly SO_VERSION=1.2.2

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
extern int xml_marker(void);
int nvat_marker(void) { return xml_marker(); }
EOF
cc -shared -fPIC -Wl,-soname,libnvat.so.1 \
    -L"${fixture}/usr/lib/x86_64-linux-gnu" \
    -Wl,-rpath-link,"${fixture}/usr/lib/x86_64-linux-gnu" \
    -o "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${temporary}/nvat.c" -lxml2
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

cache="${temporary}/cache"
stage="${temporary}/stage"
lock="${temporary}/nvattest.sha256"
binary_digest="$(sha256sum "${fixture}/usr/bin/nvattest" | cut -d' ' -f1)"
library_digest="$(sha256sum \
    "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" | cut -d' ' -f1)"
printf '%s  nvattest\n%s  libnvat.so.%s\n' \
    "${binary_digest}" "${library_digest}" "${SO_VERSION}" >"${lock}"

run_contract() {
    TINFOIL_NVATTEST_CACHE="${cache}" \
        TINFOIL_NVATTEST_LOCK="${lock}" \
        TINFOIL_NVATTEST_STAGE="${stage}" \
        "${repo_root}/scripts/nvattest-runtime.sh" "$@"
}

run_contract publish "${fixture}"
test -f "${cache}/${binary_digest}"
test -f "${cache}/${library_digest}"
test "$(stat -c %a "${cache}/${binary_digest}")" = 444
test "$(stat -c %a "${cache}/${library_digest}")" = 444
cmp "${fixture}/usr/bin/nvattest" "${stage}/usr/bin/nvattest"
cmp "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${stage}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}"
test "$(stat -c %a "${stage}/usr/bin/nvattest")" = 755
test "$(stat -c %a "${stage}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}")" = 644
test "$(stat -c %Y "${stage}/usr/bin/nvattest")" = 0
test "$(stat -c %Y "${stage}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}")" = 0

chmod u+w "${cache}/${binary_digest}"
printf 'tampered\n' >>"${cache}/${binary_digest}"
if run_contract stage 2>/dev/null; then
    echo "staging accepted a tampered cache object" >&2
    exit 1
fi
cmp "${fixture}/usr/bin/nvattest" "${stage}/usr/bin/nvattest"
install -m 0444 "${fixture}/usr/bin/nvattest" "${cache}/${binary_digest}"

rm "${cache}/${library_digest}"
if run_contract stage 2>/dev/null; then
    echo "staging accepted a missing cache object" >&2
    exit 1
fi
cmp "${fixture}/usr/bin/nvattest" "${stage}/usr/bin/nvattest"
ln -s "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${cache}/${library_digest}"
if run_contract stage 2>/dev/null; then
    echo "staging accepted a symlink cache object" >&2
    exit 1
fi
rm "${cache}/${library_digest}"
install -m 0444 "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${cache}/${library_digest}"

printf 'unexpected third entry\n' >>"${lock}"
if run_contract stage 2>/dev/null; then
    echo "staging accepted a malformed nvattest lock" >&2
    exit 1
fi
sed -i '$d' "${lock}"
run_contract stage

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
    "${temporary}/nvat.c" -lxml2
if nvattest_verify_runtime_artifacts "${fixture}" "${SO_VERSION}" 2>/dev/null; then
    echo "verification accepted an incorrect libnvat SONAME" >&2
    exit 1
fi

cc -shared -fPIC -Wl,-soname,libnvat.so.1 \
    -L"${fixture}/usr/lib/x86_64-linux-gnu" \
    -Wl,-rpath-link,"${fixture}/usr/lib/x86_64-linux-gnu" \
    -o "${fixture}/usr/lib/x86_64-linux-gnu/libnvat.so.${SO_VERSION}" \
    "${temporary}/nvat.c" -lxml2
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
