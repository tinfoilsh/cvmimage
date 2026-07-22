#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: compare_runtime_package_lock.sh CHECKED GENERATED" >&2
    exit 2
fi

cmp -- "$1" "$2"
