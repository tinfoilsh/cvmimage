#!/bin/bash
set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C

repo_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

expected_entries=$(cat <<'EOF'
.	d
etc	d
etc/group	f
etc/gshadow	f
etc/hostname	f
etc/hosts	f
etc/nsswitch.conf	f
etc/passwd	f
etc/resolv.conf	f
etc/shadow	f
EOF
)
actual_entries=$(cd image/rootfs && find . -printf '%P\t%y\n' | sed '1s/^\t/.\t/' | sort)
if [ "$actual_entries" != "$expected_entries" ]; then
    printf 'fixed rootfs policy entries differ:\n%s\n' "$actual_entries" >&2
    exit 1
fi
read -r _ root_uid root_gid <<< "$(stat -c '%a %u %g' image/rootfs)"
while IFS=$'\t' read -r path kind; do
    file=image/rootfs
    [ "$path" = . ] || file="$file/$path"
    expected_mode=644
    [ "$kind" = d ] && expected_mode=755
    metadata=$(stat -c '%a %u %g' -- "$file")
    if [ "$metadata" != "$expected_mode $root_uid $root_gid" ]; then
        echo "fixed rootfs policy metadata differs: $path: $metadata" >&2
        exit 1
    fi
    python3 - "$file" <<'PY'
import os
import sys

path = sys.argv[1]
attributes = os.listxattr(path, follow_symlinks=False)
if attributes:
    print(f"fixed rootfs policy xattrs differ: {path}: {attributes}", file=sys.stderr)
    raise SystemExit(1)
PY
done <<< "$expected_entries"

expected_files=$(printf '%s\n' "$expected_entries" | awk '$2 == "f" { print $1 }')
manifest_files=$(awk '{ print $2 }' image/rootfs-policy.sha256)
if [ "$manifest_files" != "$expected_files" ]; then
    printf 'fixed rootfs policy manifest paths differ:\n%s\n' "$manifest_files" >&2
    exit 1
fi

while read -r digest path; do
    file="image/rootfs/$path"
    if [ -L "$file" ] || [ ! -f "$file" ]; then
        echo "fixed rootfs policy path is not a regular file: $path" >&2
        exit 1
    fi
    if [ "$(stat -c %a "$file")" != 644 ]; then
        echo "fixed rootfs policy path is not mode 0644: $path" >&2
        exit 1
    fi
    printf '%s  %s\n' "$digest" "$file" | sha256sum -c -
done < image/rootfs-policy.sha256
