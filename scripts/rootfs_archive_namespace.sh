#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
    echo "rootfs archive namespace: missing command" >&2
    exit 125
fi
if [ ! -x /usr/bin/bwrap ]; then
    echo "rootfs archive namespace: /usr/bin/bwrap is unavailable" >&2
    exit 125
fi

namespace_tmp="${TEST_TMPDIR:?}/rootfs-archive-namespace-tmp"
mkdir "${namespace_tmp}"
chmod 0700 "${namespace_tmp}"
host_uid=$(id -u)
host_gid=$(id -g)
runfiles_dir=${RUNFILES_DIR:?}
test_srcdir=${TEST_SRCDIR:?}
test_workspace=${TEST_WORKSPACE:?}

exec /usr/bin/env -i /usr/bin/bwrap \
    --clearenv \
    --unshare-user \
    --uid 0 \
    --gid 0 \
    --unshare-pid \
    --unshare-ipc \
    --unshare-uts \
    --unshare-net \
    --die-with-parent \
    --new-session \
    --ro-bind / / \
    --bind "${TEST_TMPDIR:?}" "${TEST_TMPDIR}" \
    --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --setenv LC_ALL C \
    --setenv LANG C \
    --setenv PYTHONHASHSEED 0 \
    --setenv PYTHONNOUSERSITE 1 \
    --setenv PYTHONDONTWRITEBYTECODE 1 \
    --setenv RUNFILES_DIR "${runfiles_dir}" \
    --setenv TEST_SRCDIR "${test_srcdir}" \
    --setenv TEST_TMPDIR "${TEST_TMPDIR}" \
    --setenv TEST_WORKSPACE "${test_workspace}" \
    --setenv TMPDIR "${namespace_tmp}" \
    --proc /proc \
    --dev /dev \
    -- /bin/sh -eu -c '
        read uid_inside uid_outside uid_length < /proc/self/uid_map
        read gid_inside gid_outside gid_length < /proc/self/gid_map
        [ "${uid_inside}:${uid_outside}:${uid_length}" = "0:${1}:1" ]
        [ "${gid_inside}:${gid_outside}:${gid_length}" = "0:${2}:1" ]
        shift 2
        exec "$@"
    ' rootfs-archive-namespace "${host_uid}" "${host_gid}" "$@"
