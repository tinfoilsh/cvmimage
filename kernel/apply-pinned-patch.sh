#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/linux-source-7.0.0" >&2
    exit 2
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$1"
patch_path="$repo_dir/kernel/patches/0001-acpi-block-aml-private-memory.patch"
patch_sha256="82873038e3e276b62cf50433aa93c0fc44062b50adf2618851ec7a05fb07ef2a"
source_path="$source_dir/drivers/acpi/acpica/exregion.c"
source_sha256="d3d76550cadae12006bc270a863aac0ab3df4cd28938a253afd3abbd8c88f93a"
patched_sha256="47586b6be8fa550532590fb5352dbf6d980b2dc747c762e71e6bf73fea65eb96"

shopt -s nullglob
patches=("$repo_dir"/kernel/patches/*.patch)
if [ "${#patches[@]}" -ne 1 ] || [ "${patches[0]}" != "$patch_path" ]; then
    echo "kernel patch contract requires exactly $patch_path" >&2
    exit 1
fi
if [ ! -f "$patch_path" ] || [ -L "$patch_path" ]; then
    echo "kernel patch is missing or not a regular file: $patch_path" >&2
    exit 1
fi
if [ ! -f "$source_path" ]; then
    echo "unexpected kernel source tree: $source_dir" >&2
    exit 1
fi

printf '%s  %s\n' "$patch_sha256" "$patch_path" | sha256sum -c --strict --status
if ! printf '%s  %s\n' "$source_sha256" "$source_path" | sha256sum -c --strict --status; then
    echo "kernel patch preimage does not match the pinned exregion.c" >&2
    exit 1
fi
LC_ALL=C patch \
    --batch \
    --forward \
    --fuzz=0 \
    --no-backup-if-mismatch \
    --reject-file=- \
    --directory="$source_dir" \
    --strip=1 \
    < "$patch_path"
if ! printf '%s  %s\n' "$patched_sha256" "$source_path" | sha256sum -c --strict --status; then
    echo "kernel patch result does not match the pinned exregion.c contract" >&2
    exit 1
fi

if find "$source_dir" -type f \( -name '*.orig' -o -name '*.rej' \) -print -quit | grep -q .; then
    echo "kernel patch application left reject or backup files" >&2
    exit 1
fi
