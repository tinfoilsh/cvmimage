#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/kernel.config" >&2
    exit 2
fi

config="$1"
if [ ! -f "$config" ]; then
    echo "missing kernel config: $config" >&2
    exit 2
fi

failures=0

value_of() {
    local key="$1"
    if grep -Eq "^${key}=y$" "$config"; then
        echo y
    elif grep -Eq "^${key}=m$" "$config"; then
        echo m
    elif grep -Eq "^# ${key} is not set$" "$config"; then
        echo n
    else
        echo missing
    fi
}

require_value() {
    local key="$1"
    local want="$2"
    local label="$3"
    local got
    got="$(value_of "$key")"
    if [ "$got" = "$want" ]; then
        echo "OK: $label ($key=$want)"
    else
        echo "FAIL: $label ($key is $got, want $want)" >&2
        failures=$((failures + 1))
    fi
}

require_y() {
    require_value "$1" y "$2"
}

require_disabled() {
    local key="$1"
    local label="$2"
    local got
    got="$(value_of "$key")"
    case "$got" in
        n)
            echo "OK: $label ($key=n)"
            ;;
        missing)
            echo "OK: $label ($key is absent/disabled)"
            ;;
        *)
            echo "FAIL: $label ($key is $got, want n)" >&2
            failures=$((failures + 1))
            ;;
    esac
}

require_no_in_tree_modules() {
    local modules
    modules="$(grep -E '^CONFIG_[A-Za-z0-9_]+=m$' "$config" || true)"
    if [ -z "$modules" ]; then
        echo "OK: no in-tree kernel feature is configured as a module"
    else
        echo "FAIL: in-tree modules remain configured:" >&2
        printf '%s\n' "$modules" >&2
        failures=$((failures + 1))
    fi
}

echo "=== tinfoil CVM kernel allowlist ==="

require_y CONFIG_MODULES "module support remains only for the NVIDIA carve-out transition"
require_no_in_tree_modules
require_disabled CONFIG_KMOD "kernel request_module autoload helper is disabled"
require_y CONFIG_MODULE_UNLOAD "module unload ABI is temporarily kept for staged NVIDIA modules"
require_disabled CONFIG_MODULE_FORCE_LOAD "forced module loading is disabled"
require_disabled CONFIG_MODULE_FORCE_UNLOAD "forced module unloading is disabled"
require_disabled CONFIG_MODULE_UNLOAD_TAINT_TRACKING "module unload taint tracking is disabled"
require_disabled CONFIG_SECURITY_LOCKDOWN_LSM "unused inactive lockdown LSM is disabled"
require_disabled CONFIG_MODULE_SIG "unused random module-signing key generation is disabled"
require_disabled CONFIG_MICROCODE_LATE_LOADING "runtime rootfs CPU microcode loading is disabled"

for key in \
    CONFIG_SUSPEND \
    CONFIG_HIBERNATION \
    CONFIG_KEXEC \
    CONFIG_KEXEC_FILE \
    CONFIG_KEXEC_JUMP \
    CONFIG_KEXEC_HANDOVER; do
    require_disabled "$key" "guest sleep/hibernate/kexec surface is disabled"
done

for key in \
    CONFIG_PROC_KCORE \
    CONFIG_KGDB \
    CONFIG_DYNAMIC_DEBUG \
    CONFIG_COREDUMP \
    CONFIG_DEBUG_FS \
    CONFIG_KPROBES \
    CONFIG_FTRACE; do
    require_disabled "$key" "debugger-oriented kernel surface is disabled"
done

for key in \
    CONFIG_COMPAT \
    CONFIG_IA32_EMULATION \
    CONFIG_X86_X32 \
    CONFIG_X86_X32_ABI \
    CONFIG_MODIFY_LDT_SYSCALL \
    CONFIG_LEGACY_TIOCSTI \
    CONFIG_BINFMT_MISC; do
    require_disabled "$key" "unused compatibility ABI is disabled"
done

for key in \
    CONFIG_DEVMEM \
    CONFIG_DEVPORT \
    CONFIG_X86_IOPL_IOPERM \
    CONFIG_ACPI_TABLE_UPGRADE \
    CONFIG_EFI_CUSTOM_SSDT_OVERLAYS \
    CONFIG_LIVEPATCH; do
    require_disabled "$key" "privileged kernel-management interface is disabled"
done

for key in \
    CONFIG_SLAB_FREELIST_RANDOM \
    CONFIG_RANDOM_KMALLOC_CACHES \
    CONFIG_SHUFFLE_PAGE_ALLOCATOR \
    CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT \
    CONFIG_ZERO_CALL_USED_REGS \
    CONFIG_INIT_ON_ALLOC_DEFAULT_ON \
    CONFIG_INIT_ON_FREE_DEFAULT_ON \
    CONFIG_RANDOMIZE_BASE \
    CONFIG_RANDOMIZE_MEMORY \
    CONFIG_X86_USER_SHADOW_STACK \
    CONFIG_STRICT_MODULE_RWX \
    CONFIG_SECCOMP_FILTER \
    CONFIG_SECURITY_YAMA \
    CONFIG_SECURITY_LANDLOCK \
    CONFIG_HARDENED_USERCOPY \
    CONFIG_SECURITY_DMESG_RESTRICT \
    CONFIG_IOMMU_DEFAULT_DMA_STRICT \
    CONFIG_LEGACY_VSYSCALL_NONE \
    CONFIG_BPF_SYSCALL \
    CONFIG_BPF_JIT_ALWAYS_ON \
    CONFIG_BPF_UNPRIV_DEFAULT_OFF \
    CONFIG_CGROUP_BPF \
    CONFIG_WERROR; do
    require_y "$key" "production kernel hardening is enabled"
done

require_disabled CONFIG_SLAB_MERGE_DEFAULT "slab cache merging is disabled"
require_disabled CONFIG_SECURITY_SELINUX "unused SELinux implementation is disabled"
require_disabled CONFIG_SECURITY_APPARMOR "unused AppArmor implementation is disabled"
require_disabled CONFIG_KFENCE "KFENCE is reserved for validation kernels"

for key in \
    CONFIG_BLK_DEV_INITRD \
    CONFIG_DEVTMPFS \
    CONFIG_DEVTMPFS_MOUNT \
    CONFIG_CONFIGFS_FS \
    CONFIG_PROC_FS \
    CONFIG_SYSFS \
    CONFIG_TMPFS \
    CONFIG_BLK_DEV_DM \
    CONFIG_BLK_DEV_DM_BUILTIN \
    CONFIG_DM_BUFIO \
    CONFIG_DM_VERITY \
    CONFIG_DM_CRYPT \
    CONFIG_EXT4_FS \
    CONFIG_OVERLAY_FS \
    CONFIG_EROFS_FS \
    CONFIG_BLK_DEV_LOOP; do
    require_y "$key" "boot/root/model filesystem path is built in"
done
require_disabled CONFIG_DM_UEVENT "device-mapper uevent generation is disabled"

for key in \
    CONFIG_SCSI \
    CONFIG_BLK_DEV_SD \
    CONFIG_VIRTIO \
    CONFIG_VIRTIO_PCI \
    CONFIG_VIRTIO_BLK \
    CONFIG_SCSI_VIRTIO \
    CONFIG_VIRTIO_CONSOLE \
    CONFIG_VSOCKETS \
    CONFIG_VIRTIO_VSOCKETS \
    CONFIG_VIRTIO_VSOCKETS_COMMON; do
    require_y "$key" "fixed virtio/QEMU device path is built in"
done

for key in \
    CONFIG_VIRTIO_NET \
    CONFIG_TUN \
    CONFIG_VETH \
    CONFIG_LLC \
    CONFIG_STP \
    CONFIG_BRIDGE \
    CONFIG_BRIDGE_NETFILTER \
    CONFIG_NETFILTER \
    CONFIG_NETFILTER_NETLINK \
    CONFIG_NF_CONNTRACK \
    CONFIG_NF_CT_NETLINK \
    CONFIG_NF_NAT \
    CONFIG_NF_TABLES \
    CONFIG_NFT_CT \
    CONFIG_NFT_NAT \
    CONFIG_NFT_COMPAT \
    CONFIG_NETFILTER_XTABLES \
    CONFIG_IP6_NF_IPTABLES \
    CONFIG_NETFILTER_XT_SET \
    CONFIG_NETFILTER_XT_NAT \
    CONFIG_NETFILTER_XT_TARGET_MASQUERADE \
    CONFIG_NETFILTER_XT_MATCH_ADDRTYPE \
    CONFIG_NETFILTER_XT_MATCH_CONNTRACK \
    CONFIG_IP_SET \
    CONFIG_IP_SET_HASH_IP \
    CONFIG_IP_SET_HASH_NET \
    CONFIG_NET_SCH_FQ_CODEL; do
    require_y "$key" "Docker bridge/nftables path is built in"
done

for key in \
    CONFIG_CRYPTO_SHA256 \
    CONFIG_CRYPTO_SHA512 \
    CONFIG_CRYPTO_AES \
    CONFIG_CRYPTO_AES_NI_INTEL \
    CONFIG_CRYPTO_ECDSA; do
    require_y "$key" "dm/NVIDIA crypto prerequisite is built in"
done

for key in \
    CONFIG_TDX_GUEST_DRIVER \
    CONFIG_TSM_REPORTS \
    CONFIG_SEV_GUEST; do
    require_y "$key" "confidential-computing attestation path is built in"
done

for key in \
    CONFIG_ACPI_VIDEO \
    CONFIG_ACPI_WMI; do
    require_y "$key" "B300 NVIDIA compatibility prerequisite is built in"
done

for key in \
    CONFIG_HOTPLUG_PCI \
    CONFIG_USB_SUPPORT \
    CONFIG_BT \
    CONFIG_WLAN \
    CONFIG_SOUND \
    CONFIG_XEN \
    CONFIG_HYPERV \
    CONFIG_ATA \
    CONFIG_FUSE_FS \
    CONFIG_VFAT_FS \
    CONFIG_DRM \
    CONFIG_FB \
    CONFIG_VT \
    CONFIG_WATCHDOG \
    CONFIG_X86_SGX \
    CONFIG_TCG_TPM \
    CONFIG_AGP \
    CONFIG_MMC \
    CONFIG_EDAC \
    CONFIG_REMOTEPROC \
    CONFIG_PM_DEVFREQ \
    CONFIG_POWERCAP \
    CONFIG_LIBNVDIMM \
    CONFIG_DAX \
    CONFIG_SQUASHFS \
    CONFIG_FS_ENCRYPTION \
    CONFIG_FS_VERITY \
    CONFIG_INTEGRITY \
    CONFIG_IMA \
    CONFIG_EVM; do
    require_disabled "$key" "unneeded hypervisor-presentable device family is disabled"
done

if [ "$failures" -ne 0 ]; then
    echo "kernel config check failed with $failures issue(s)" >&2
    exit 1
fi

echo "kernel config check passed"
