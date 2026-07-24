#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/linux-source-7.0.0" >&2
    exit 2
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$1"
patch_path="$repo_dir/kernel/patches/0001-acpi-block-aml-private-memory.patch"
patch_sha256="81a9457033f3acb2a3cd6bd3e070c8d525e26298519660e68dca4eccac10cb54"
source_path="$source_dir/drivers/acpi/acpica/exregion.c"
source_sha256="d3d76550cadae12006bc270a863aac0ab3df4cd28938a253afd3abbd8c88f93a"
patched_sha256="73916ed7297e1aa52644b3b9f4a1b3aae4ef2543024d2029b54d4945ce49823f"

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
if [ ! -f "$source_path" ] || [ -L "$source_path" ]; then
    echo "unexpected kernel source tree: $source_dir" >&2
    exit 1
fi

printf '%s  %s\n' "$patch_sha256" "$patch_path" | sha256sum -c --strict --status
if ! printf '%s  %s\n' "$source_sha256" "$source_path" | sha256sum -c --strict --status; then
    echo "kernel patch preimage does not match the pinned exregion.c" >&2
    exit 1
fi
scratch="$(mktemp -d "${TMPDIR:-/tmp}/tinfoil-kernel-patch.XXXXXXXX")"
staged_path=""
cleanup() {
    rm -rf -- "$scratch"
    if [ -n "$staged_path" ]; then
        rm -f -- "$staged_path"
    fi
}
trap cleanup EXIT

scratch_source="$scratch/drivers/acpi/acpica/exregion.c"
mkdir -p "$(dirname -- "$scratch_source")"
cp -p -- "$source_path" "$scratch_source"

LC_ALL=C patch \
    --batch \
    --forward \
    --fuzz=0 \
    --no-backup-if-mismatch \
    --reject-file=- \
    --directory="$scratch" \
    --strip=1 \
    < "$patch_path"
if ! printf '%s  %s\n' "$patched_sha256" "$scratch_source" | sha256sum -c --strict --status; then
    echo "kernel patch result does not match the pinned exregion.c contract" >&2
    exit 1
fi

if find "$scratch" -type f \( -name '*.orig' -o -name '*.rej' \) -print -quit | grep -q .; then
    echo "kernel patch application left reject or backup files" >&2
    exit 1
fi

staged_path="$(mktemp "$source_path.tinfoil-patch.XXXXXXXX")"
cat -- "$scratch_source" > "$staged_path"
chmod --reference="$source_path" "$staged_path"
if ! printf '%s  %s\n' "$patched_sha256" "$staged_path" | sha256sum -c --strict --status; then
    echo "staged kernel patch result does not match the pinned exregion.c contract" >&2
    exit 1
fi
mv -fT -- "$staged_path" "$source_path"
staged_path=""
