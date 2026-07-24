#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source "${repo_root}/scripts/nvattest-artifacts.sh"
readonly SO_VERSION="${NVATTEST_RUNTIME_SO_VERSION}"

test "${NVATTEST_RUNTIME_SO_VERSION}" = 1.2.2
test "${NVATTEST_RUNTIME_BINARY_SHA256}" = \
    ef18d634cbcd9903baaedc6ed164af765175e88df3831f323c61ffe47c4109ed
test "${NVATTEST_RUNTIME_LIBRARY_SHA256}" = \
    cbf70893dba2f554f8c218cb009705d09f62573db10b48994ffd8d66306c1e07

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

export LD_LIBRARY_PATH="${fixture}/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
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

cp "${fixture}/usr/bin/nvattest" \
    "${cache}/sha256/${binary_sha256}/nvattest"
rm "${cache}/sha256/${library_sha256}/libnvat.so.${SO_VERSION}"
if nvattest_stage_content_addressed_runtime_artifacts \
    "${cache}" "${temporary}/missing-library-output" "${SO_VERSION}" \
    "${binary_sha256}" "${library_sha256}" "$(id -u)" "$(id -g)" 0 \
    2>"${temporary}/missing-library.log"; then
    echo "cache staging accepted a missing libnvat library" >&2
    exit 1
fi
grep -Fq 'missing cached libnvat' "${temporary}/missing-library.log"

printf 'mismatch\n' \
    >"${cache}/sha256/${library_sha256}/libnvat.so.${SO_VERSION}"
if nvattest_stage_content_addressed_runtime_artifacts \
    "${cache}" "${temporary}/mismatch-library-output" "${SO_VERSION}" \
    "${binary_sha256}" "${library_sha256}" "$(id -u)" "$(id -g)" 0 \
    2>"${temporary}/mismatch-library.log"; then
    echo "cache staging accepted a mismatched libnvat library" >&2
    exit 1
fi
grep -Fq 'cached libnvat SHA-256 mismatch' \
    "${temporary}/mismatch-library.log"

malformed_cache="${temporary}/malformed-cache"
mkdir -p "${malformed_cache}/sha256/${binary_sha256}/nvattest"
if nvattest_publish_content_addressed_runtime_artifacts \
    "${fixture}" "${malformed_cache}" "${SO_VERSION}" \
    "${binary_sha256}" "${library_sha256}" 2>"${temporary}/malformed.log"; then
    echo "cache publication accepted a directory as the nvattest artifact" >&2
    exit 1
fi
grep -Fq 'cached nvattest destination is not a regular file' \
    "${temporary}/malformed.log"

copy_race_cache="${temporary}/copy-race-cache"
(
    install() {
        command install "$@"
        case "${!#}" in
            */nvattest.tmp.*) printf 'replaced\n' >>"${!#}" ;;
        esac
    }
    if nvattest_publish_content_addressed_runtime_artifacts \
        "${fixture}" "${copy_race_cache}" "${SO_VERSION}" \
        "${binary_sha256}" "${library_sha256}" 2>/dev/null; then
        echo "cache publication accepted changed copied bytes" >&2
        exit 1
    fi
)
test ! -e "${copy_race_cache}/sha256/${binary_sha256}/nvattest"

rollback_cache="${temporary}/rollback-cache"
(
    move_count=0
    mv() {
        move_count=$((move_count + 1))
        if [ "${move_count}" -eq 2 ]; then
            return 1
        fi
        command mv "$@"
    }
    if nvattest_publish_content_addressed_runtime_artifacts \
        "${fixture}" "${rollback_cache}" "${SO_VERSION}" \
        "${binary_sha256}" "${library_sha256}" 2>/dev/null; then
        echo "cache publication ignored a partial publication failure" >&2
        exit 1
    fi
)
test ! -e "${rollback_cache}/sha256/${binary_sha256}/nvattest"
test ! -e \
    "${rollback_cache}/sha256/${library_sha256}/libnvat.so.${SO_VERSION}"

if "${repo_root}/scripts/reproduce-nvattest.sh" --publish-cache '' \
    >/dev/null 2>&1; then
    echo "reproducibility accepted an empty cache root" >&2
    exit 1
fi
if "${repo_root}/scripts/regenerate-nvattest-cache.sh" '' \
    >/dev/null 2>&1; then
    echo "regeneration accepted an empty cache root" >&2
    exit 1
fi
if "${repo_root}/scripts/stage-nvattest-cache.sh" '' output \
    >/dev/null 2>&1; then
    echo "staging accepted an empty cache root" >&2
    exit 1
fi

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
