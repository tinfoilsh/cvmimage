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

exec /usr/bin/bwrap \
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
