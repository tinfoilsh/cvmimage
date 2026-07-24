#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_dir="$repo_dir/kernel"
kernel_source_version="7.0.0"
kernel_package_version="7.0.0-28.28"
kernel_source_deb_sha256="dd5994b199a1cb06b1f336bb086c5c23a9258fdcfdcbb7dcc8d3afa9a5d92e13"
source_sha256="d3d76550cadae12006bc270a863aac0ab3df4cd28938a253afd3abbd8c88f93a"
deb_name="linux-source-${kernel_source_version}_${kernel_package_version}_all.deb"
source_deb_url="https://archive.ubuntu.com/ubuntu/pool/main/l/linux/${deb_name}"

scratch="$(mktemp -d "${TMPDIR:-/tmp}/tinfoil-acpi-patch-test.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

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
    if [ "${TINFOIL_OFFLINE:-0}" = 1 ]; then
        echo "missing pinned offline kernel source package: $deb_name" >&2
        exit 2
    fi
    curl -fsSL --retry 3 "$source_deb_url" -o "$scratch/$deb_name"
    source_deb="$scratch/$deb_name"
fi

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
if [ "$(grep -Fc '#if defined(CONFIG_ARCH_HAS_CC_PLATFORM) && defined(CONFIG_X86)' "$exregion")" -ne 2 ]; then
    echo "ACPI private-memory guard is not restricted to both x86 call sites" >&2
    exit 1
fi
grep -Fq 'entry = lookup_address(page, &level);' "$exregion"
grep -Fq 'pte_val(entry_value) != cc_mkdec(pte_val(entry_value))' "$exregion"
grep -Fq 'if (page == (end & PAGE_MASK))' "$exregion"
grep -Fq 'return_ACPI_STATUS(AE_AML_ILLEGAL_ADDRESS);' "$exregion"

helper="$(awk '
    /^static bool acpi_ex_system_memory_access_allowed/ {
        if (found) exit 2
        found = 1
    }
    found { print }
    found && /^}$/ {
        closed = 1
        exit
    }
    END { if (!found || !closed) exit 1 }
' "$exregion")" || {
    echo "ACPI private-memory guard helper is missing or malformed" >&2
    exit 1
}
if printf '%s\n' "$helper" | grep -Eq '(pr_[[:alnum:]_]*|printk|ACPI_(DEBUG_PRINT|ERROR|INFO)|schedule|cond_resched)[[:space:]]*\('; then
    echo "ACPI private-memory guard contains forbidden debug or mutable-state machinery" >&2
    exit 1
fi
added_lines="$(awk '/^\+[^+]/ { sub(/^\+/, ""); print }' "$kernel_dir/patches/0001-acpi-block-aml-private-memory.patch")"
if [ "$(printf '%s\n' "$added_lines" | grep -Ec '^[[:space:]]*static[[:space:]]')" -ne 1 ] ||
    ! printf '%s\n' "$added_lines" | grep -Fqx 'static bool acpi_ex_system_memory_access_allowed(void *logical_address,'; then
    echo "ACPI private-memory patch adds forbidden static state or helpers" >&2
    exit 1
fi

transaction_source="$scratch/transaction-source/linux-source-${kernel_source_version}"
mkdir -p "$(dirname -- "$transaction_source/drivers/acpi/acpica/exregion.c")"
tar -xaf "$source_tarball" -C "$scratch/transaction-source" \
    "linux-source-${kernel_source_version}/drivers/acpi/acpica/exregion.c"
transaction_repo="$scratch/transaction-repo"
mkdir -p "$transaction_repo/kernel/patches"
cp -- "$kernel_dir/apply-pinned-patch.sh" "$transaction_repo/kernel/apply-pinned-patch.sh"
cp -- "$kernel_dir/patches/0001-acpi-block-aml-private-memory.patch" \
    "$transaction_repo/kernel/patches/0001-acpi-block-aml-private-memory.patch"
sed -i 's/^patched_sha256=.*/patched_sha256="0000000000000000000000000000000000000000000000000000000000000000"/' \
    "$transaction_repo/kernel/apply-pinned-patch.sh"
if "$transaction_repo/kernel/apply-pinned-patch.sh" "$transaction_source" >"$scratch/transaction.log" 2>&1; then
    echo "kernel patch unexpectedly accepted an invalid postimage contract" >&2
    exit 1
fi
printf '%s  %s\n' "$source_sha256" "$transaction_source/drivers/acpi/acpica/exregion.c" |
    sha256sum -c --strict --status

symlink_source="$scratch/symlink-source/linux-source-${kernel_source_version}"
symlink_target="$scratch/symlink-exregion.c"
mkdir -p "$(dirname -- "$symlink_source/drivers/acpi/acpica/exregion.c")"
cp -- "$transaction_source/drivers/acpi/acpica/exregion.c" "$symlink_target"
ln -s "$symlink_target" "$symlink_source/drivers/acpi/acpica/exregion.c"
if "$kernel_dir/apply-pinned-patch.sh" "$symlink_source" >"$scratch/symlink.log" 2>&1; then
    echo "kernel patch unexpectedly accepted a symlinked source file" >&2
    exit 1
fi
printf '%s  %s\n' "$source_sha256" "$symlink_target" | sha256sum -c --strict --status

if "$kernel_dir/apply-pinned-patch.sh" "$source_dir" >"$scratch/reapply.log" 2>&1; then
    echo "kernel patch unexpectedly applied twice" >&2
    exit 1
fi

echo "pinned ACPI AML patch source contract passed"
