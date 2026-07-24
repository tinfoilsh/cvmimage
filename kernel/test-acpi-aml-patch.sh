#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"
kernel_source_version="7.0.0"
kernel_package_version="7.0.0-28.28"
kernel_source_deb_sha256="dd5994b199a1cb06b1f336bb086c5c23a9258fdcfdcbb7dcc8d3afa9a5d92e13"
deb_name="linux-source-${kernel_source_version}_${kernel_package_version}_all.deb"

source_deb=""
for candidate in \
    "${TINFOIL_KERNEL_SOURCE_DEB:-}" \
    "$kernel_dir/build/debs/$deb_name" \
    "/opt/tinfoil-builder/packages/$deb_name" \
    "/var/cache/apt/archives/$deb_name"; do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        source_deb="$candidate"
        break
    fi
done
if [ -z "$source_deb" ]; then
    echo "missing pinned kernel source package: $deb_name" >&2
    exit 2
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/tinfoil-acpi-patch-test.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

printf '%s  %s\n' "$kernel_source_deb_sha256" "$source_deb" | sha256sum -c --strict --status
dpkg-deb -x "$source_deb" "$scratch/package"
source_tarball="$(find "$scratch/package/usr/src" -type f -name "linux-source-${kernel_source_version}.tar.*" -print -quit)"
if [ -z "$source_tarball" ]; then
    echo "pinned source package did not contain the expected source tarball" >&2
    exit 1
fi

mkdir -p "$scratch/source"
tar -xaf "$source_tarball" -C "$scratch/source" \
    "linux-source-${kernel_source_version}/drivers/acpi/acpica/exregion.c"
source_dir="$scratch/source/linux-source-${kernel_source_version}"
"$kernel_dir/apply-pinned-patch.sh" "$source_dir"

exregion="$source_dir/drivers/acpi/acpica/exregion.c"
grep -Fq 'cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT)' "$exregion"
grep -Fq 'entry = lookup_address(page, &level);' "$exregion"
grep -Fq 'pte_val(entry_value) != cc_mkdec(pte_val(entry_value))' "$exregion"
grep -Fq 'if (page == (end & PAGE_MASK))' "$exregion"
grep -Fq 'return_ACPI_STATUS(AE_AML_ILLEGAL_ADDRESS);' "$exregion"

helper="$(sed -n '/static bool acpi_ex_system_memory_access_allowed/,/^#endif$/p' "$exregion")"
if printf '%s\n' "$helper" | grep -Eq 'pr_|ACPI_(ERROR|INFO)|cond_resched|static struct'; then
    echo "ACPI private-memory guard contains forbidden debug or mutable-state machinery" >&2
    exit 1
fi
if "$kernel_dir/apply-pinned-patch.sh" "$source_dir" >"$scratch/reapply.log" 2>&1; then
    echo "kernel patch unexpectedly applied twice" >&2
    exit 1
fi

echo "pinned ACPI AML patch source contract passed"
