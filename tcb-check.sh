#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
rootfs="${1:-}"
failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

ok() {
    echo "OK: $*"
}

package_list() {
    awk '
        /^Packages=/ { in_pkg=1; next }
        /^\[/ { in_pkg=0 }
        in_pkg && NF {
            name=$1
            sub(/=.*/, "", name)
            print name
        }
    ' "$repo_dir/mkosi.conf"
}

has_package() {
    local packages
    packages="$(package_list)"
    grep -Fxq -- "$1" <<<"$packages"
}

require_file_contains() {
    local file="$1"
    local pattern="$2"
    local label="$3"
    if grep -Eq -- "$pattern" "$file"; then
        ok "$label"
    else
        fail "$label"
    fi
}

require_file_not_contains() {
    local file="$1"
    local pattern="$2"
    local label="$3"
    if grep -Eq -- "$pattern" "$file"; then
        fail "$label"
    else
        ok "$label"
    fi
}

require_path_absent() {
    local path="$1"
    local label="$2"
    if [ -e "$path" ]; then
        fail "$label"
    else
        ok "$label"
    fi
}

require_file_order() {
    local file="$1"
    local first_pattern="$2"
    local second_pattern="$3"
    local label="$4"
    local first_line second_line
    first_line="$(grep -nE -- "$first_pattern" "$file" | head -n 1 | cut -d: -f1 || true)"
    second_line="$(grep -nE -- "$second_pattern" "$file" | head -n 1 | cut -d: -f1 || true)"
    if [ -n "$first_line" ] && [ -n "$second_line" ] && [ "$first_line" -lt "$second_line" ]; then
        ok "$label"
    else
        fail "$label"
    fi
}

echo "=== source config ==="
# cryptsetup is still a runtime package at this stage: the EMWP dm-crypt path
# shells out to it until the direct dm-crypt change removes it (and re-adds it
# to this exclusion list).
for pkg in ubuntu-standard nano iputils-ping curl procps systemd systemd-boot systemd-boot-tools systemd-resolved systemd-cryptsetup udev kmod mount docker-ce docker-ce-cli containerd.io; do
    if has_package "$pkg"; then
        fail "mkosi.conf must not include runtime package $pkg"
    else
        ok "mkosi.conf excludes $pkg"
    fi
done

if has_package "systemd-boot-efi"; then
    ok "mkosi.conf keeps only the split systemd EFI stub package"
else
    fail "mkosi.conf must include systemd-boot-efi until mkosi's UKI stub is supplied another way"
fi

for pkg in build-essential patch linux-headers-generic; do
    if has_package "$pkg"; then
        ok "$pkg is a transient build input pruned by mkosi.finalize"
    fi
done

require_file_contains "$repo_dir/mkosi.conf" '^Bootloader=uki$' "mkosi uses direct UKI boot path without systemd-boot manager"
require_file_contains "$repo_dir/mkosi.conf" '^KernelModulesInitrd=no$' "mkosi does not synthesize a builder-managed kernel module initrd"
require_file_not_contains "$repo_dir/mkosi.conf" '^KernelModulesInitrdInclude=' "mkosi has no stale builder-managed initrd module include list"
require_file_contains "$repo_dir/mkosi.conf" '^WithDocs=false$' "mkosi disables documentation"
require_file_contains "$repo_dir/mkosi.conf" '^CleanPackageMetadata=true$' "mkosi cleans package metadata"
require_file_contains "$repo_dir/mkosi.conf" '^WithRecommends=false$' "mkosi disables recommended packages"
require_file_contains "$repo_dir/mkosi.repart/10-root.conf" '^ExcludeFilesTarget=/usr/lib/systemd$' "root partition excludes mkosi UKI stub source from runtime rootfs"
require_file_not_contains "$repo_dir/mkosi.conf" '^[[:space:]]+nls_$' "mkosi initrd allowlist excludes broad NLS charset modules"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+bash$' "initrd package set excludes bash"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+dash$' "initrd package set excludes dash"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+coreutils$' "initrd package set excludes coreutils"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+mount$' "initrd package set excludes mount"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+util-linux-extra$' "initrd package set excludes util-linux-extra"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+cryptsetup$' "initrd package set excludes cryptsetup"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+dmsetup$' "initrd package set excludes dmsetup"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+kmod$' "initrd package set excludes kmod"
require_file_contains "$repo_dir/Makefile" 'tinfoil-initrd \./cmd/initrd' "build produces compiled Tinfoil initrd entrypoint"
require_file_contains "$repo_dir/Makefile" 'ln -s usr/bin/tinfoil-initrd mkosi\.images/initrd/mkosi\.extra/init' "build links /init to compiled Tinfoil initrd entrypoint"
require_file_not_contains "$repo_dir/Makefile" '^rebuild:.*initrd-modules' "default rebuild does not stage initrd module payload"
require_file_contains "$repo_dir/Makefile" '^rebuild:.*initrd-no-modules' "default rebuild clears stale initrd module payload"
require_file_not_contains "$repo_dir/tinfoil/cmd/initrd/main.go" '"/usr/bin/sh"|"/bin/sh"|switch_root|systemd/systemd|tinfoil-pid1|/usr/sbin/(veritysetup|dmsetup)' "compiled initrd source has no shell/veritysetup/dmsetup/systemd fallback"
require_file_not_contains "$repo_dir/tinfoil/cmd/initrd/main.go" '/usr/sbin/modprobe|exec\.Command|InitModule' "compiled initrd source has no modprobe or broad module loader execution path"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'unix\.FinitModule' "compiled initrd uses direct finit_module for the bounded module manifest"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'parseModuleManifest' "compiled initrd validates the bounded module manifest"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'tinfoil-initrd-modules' "compiled initrd has an explicit custom-kernel module mode selector"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'is required on the kernel cmdline' "compiled initrd requires an explicit dm-target module mode (fails closed)"
require_file_contains "$repo_dir/mkosi.conf" '^KernelCommandLine=.*tinfoil-initrd-modules=' "image pins an explicit initrd dm-target module mode"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'skipping bounded initrd module loader: dm targets are built into the kernel' "compiled initrd can skip module loading for the built-in dm target mode"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main_test.go" 'TestCmdlineValueFrom' "initrd command-line mode parsing is tested"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main_test.go" 'TestInitrdModuleModeFromRequiresExplicitMode' "initrd fail-closed on missing dm-target mode is tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'runtimeKernelModuleBuiltIn' "runtime module loader recognizes exact built-in module paths for the custom-kernel transition"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules_test.go" 'TestLoadRuntimeKernelModuleSkipsExactBuiltIn' "runtime module loader has built-in module coverage"
require_file_contains "$repo_dir/Makefile" 'custom-kernel-builtins' "Makefile stages custom kernel built-in manifest for rootfs assembly"
require_file_contains "$repo_dir/mkosi.finalize" 'install_custom_kernel_builtins' "finalize installs custom kernel built-in manifest after depmod"
require_file_contains "$repo_dir/mkosi.finalize" 'custom_kernel_builtin_manifest' "finalize consumes the staged custom kernel built-in manifest"
require_file_not_contains "$repo_dir/mkosi.finalize" 'updates/dkms/nvidia\*\.ko' "finalize does not keep wildcard stock NVIDIA DKMS modules"
require_file_not_contains "$repo_dir/mkosi.postinst.chroot" 'systemctl' "postinstall does not require systemctl"
require_file_not_contains "$repo_dir/mkosi.postinst.chroot" '/root/\.bashrc' "postinstall does not create root bashrc"
require_path_absent "$repo_dir/mkosi.extra/usr/local/bin/tinfoil-ramdisk" "ramdisk setup is no longer a root shell helper"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'setupRamdisk' "Tinfoil PID1 owns ramdisk setup"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'ramdiskSizeGBFrom' "ramdisk sizing reads kernel memory info directly from PID1"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestRamdiskSizeGBFromMeminfo' "ramdisk sizing policy is unit tested"
require_path_absent "$repo_dir/mkosi.extra/usr/local/bin/check-nvidia-gpu" "NVIDIA GPU discovery is no longer a root shell helper"
require_path_absent "$repo_dir/mkosi.extra/usr/local/bin/check-nvidia-fabric" "NVIDIA fabric discovery is no longer a root shell helper"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/x86_64-linux-gnu/security/pam_\*\.so' "finalize removes PAM module policy surface"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/cryptsetup' "finalize removes cryptsetup helper scripts"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/bash' "finalize removes rootfs bash"
require_file_contains "$repo_dir/mkosi.finalize" '/bin/sh' "finalize points root shell at POSIX sh"
require_file_contains "$repo_dir/Makefile" '\./install-static-docker\.sh' "Makefile installs static Docker bundle"
if [ -x "$repo_dir/install-static-docker.sh" ]; then
    ok "static Docker installer exists and is executable"
else
    fail "install-static-docker.sh must exist and be executable"
fi
require_file_contains "$repo_dir/install-static-docker.sh" 'docker_static_version="29\.5\.3"' "static Docker installer pins the Docker version"
require_file_contains "$repo_dir/install-static-docker.sh" '34eea64e9c3435f5af1b760827a56a561cd67fc2d6e9cd1813b8bb1e3ff7930b' "static Docker installer verifies the tarball hash"
require_file_contains "$repo_dir/install-static-docker.sh" 'lib\(systemd\|udev\)\\\.so' "static Docker installer rejects systemd/udev ELF dependencies"
require_file_not_contains "$repo_dir/mkosi.postinst.chroot" 'cc .*libsystemd|libsystemd-journal-shim|ln -sfn .*libsystemd' "postinstall does not create a libsystemd compatibility shim"
source_libsystemd_shim="$(
    find "$repo_dir/mkosi.extra/opt/tinfoil-shims" -mindepth 1 -print -quit 2>/dev/null \
    || true
)"
if [ -n "$source_libsystemd_shim" ]; then
    fail "source tree still ships libsystemd compatibility shim ${source_libsystemd_shim#$repo_dir/}"
else
    ok "source tree ships no libsystemd compatibility shim"
fi
if [ -x "$repo_dir/build-libdevmapper-noudev.sh" ]; then
    ok "no-udev libdevmapper build helper exists and is executable"
else
    fail "build-libdevmapper-noudev.sh must exist and be executable"
fi
require_file_contains "$repo_dir/build-libdevmapper-noudev.sh" '--without-udev' "libdevmapper build disables udev support"
require_file_contains "$repo_dir/build-libdevmapper-noudev.sh" '--disable-udev_sync' "libdevmapper build disables udev synchronization"
require_file_contains "$repo_dir/build-libdevmapper-noudev.sh" '--disable-udev_rules' "libdevmapper build disables udev rules"
require_file_contains "$repo_dir/build-libdevmapper-noudev.sh" '--disable-selinux' "libdevmapper build disables selinux dependency"
require_file_contains "$repo_dir/build-libdevmapper-noudev.sh" 'tinfoil-libdevmapper-noudev-v1' "libdevmapper build embeds Tinfoil no-udev marker"
require_file_contains "$repo_dir/build-libdevmapper-noudev.sh" 'dm_udev_create_cookie' "libdevmapper build preserves compatibility udev cookie export"
require_file_contains "$repo_dir/Makefile" '\./build-libdevmapper-noudev\.sh' "Makefile shims target builds no-udev libdevmapper"
require_file_contains "$repo_dir/mkosi.postinst.chroot" 'tinfoil-libdevmapper-noudev-v1' "postinstall validates no-udev libdevmapper marker"
require_file_contains "$repo_dir/mkosi.postinst.chroot" 'libudev\.so\.1\.\*' "postinstall removes libudev shared objects"
require_file_contains "$repo_dir/mkosi.finalize" 'tinfoil-libdevmapper-noudev-v1' "finalize validates no-udev libdevmapper marker"
require_file_contains "$repo_dir/mkosi.finalize" 'libudev-tinfoil-inactive-shim\.so\.1' "finalize removes stale inactive libudev shim"
require_file_contains "$repo_dir/mkosi.finalize" '/opt/tinfoil-shims' "finalize removes shim build sources"
require_file_contains "$repo_dir/mkosi.finalize" 'Tinfoil CVM static resolver' "finalize installs static resolver"
require_file_contains "$repo_dir/mkosi.finalize" 'nameserver 1\.1\.1\.1' "static resolver uses host-advertised primary DNS"
require_file_contains "$repo_dir/mkosi.finalize" 'nameserver 1\.0\.0\.1' "static resolver uses host-advertised secondary DNS"
require_file_contains "$repo_dir/mkosi.finalize" 'hosts: files dns' "finalize removes nss-resolve from host lookup path"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-networkd-resolve-hook\.socket' "finalize removes stale networkd resolve hook"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-networkd-wait-online\.service' "finalize removes stale networkd wait-online install hook"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-network-generator\.service' "finalize removes stale networkd generator install hook"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-networkd-varlink\.socket' "finalize removes networkd varlink socket"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-udevd-varlink\.socket' "finalize removes udevd varlink socket"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-journald-audit\.socket' "finalize removes journald audit socket"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-journald-dev-log\.socket' "finalize removes journald dev-log socket"
require_file_contains "$repo_dir/mkosi.finalize" 'CAP_AUDIT_READ' "finalize removes journald audit capabilities"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-sysusers\.service' "finalize removes sysusers service"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/systemd-sysusers' "finalize removes sysusers binary"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/sysusers\.d' "finalize removes sysusers config"
require_file_contains "$repo_dir/mkosi.finalize" 'Tinfoil CVM minimal tmpfiles policy' "finalize installs minimal tmpfiles policy"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-tmpfiles-setup-dev' "finalize removes tmpfiles dev units"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-tmpfiles-clean\.service' "finalize removes tmpfiles clean service"
require_file_contains "$repo_dir/mkosi.finalize" '\^ImportCredential=' "finalize removes tmpfiles credential imports"
require_file_contains "$repo_dir/mkosi.finalize" 'Tinfoil CVM minimal sysctl policy' "finalize installs minimal sysctl policy"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/sysctl\.d' "finalize removes stock sysctl policy"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/sysctl' "finalize removes sysctl CLI"
require_file_contains "$repo_dir/mkosi.finalize" '\^ImportCredential=sysctl' "finalize removes sysctl credential imports"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-random-seed\.service' "finalize removes random-seed service"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/systemd-random-seed' "finalize removes random-seed helper"
require_file_contains "$repo_dir/mkosi.finalize" '/var/lib/systemd/random-seed' "finalize removes random-seed state file"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-udevd-varlink\.socket' "initrd finalize removes udevd varlink socket"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-journald-audit\.socket' "initrd finalize removes journald audit socket"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-journald-dev-log\.socket' "initrd finalize removes journald dev-log socket"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-sysusers\.service' "initrd finalize removes sysusers service"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/bin/systemd-sysusers' "initrd finalize removes sysusers binary"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/sysusers\.d' "initrd finalize removes sysusers config"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'Tinfoil CVM minimal tmpfiles policy' "initrd finalize installs minimal tmpfiles policy"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-tmpfiles-setup-dev' "initrd finalize removes tmpfiles dev units"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-tmpfiles-clean\.service' "initrd finalize removes tmpfiles clean service"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '\^ImportCredential=' "initrd finalize removes tmpfiles credential imports"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/etc/systemd/user' "initrd finalize removes user-manager units"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-sysctl\.service' "initrd finalize removes sysctl service"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/systemd-sysctl' "initrd finalize removes sysctl helper"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/sysctl\.d' "initrd finalize removes sysctl policy"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-random-seed\.service' "initrd finalize removes random-seed service"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/systemd-random-seed' "initrd finalize removes random-seed helper"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/var/lib/systemd/random-seed' "initrd finalize removes random-seed state file"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'libdevmapper\.so\.1\.02\.1' "initrd finalize removes libdevmapper"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'libkmod\.so\.2' "initrd finalize removes libkmod"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'libcrypto\.so\.3' "initrd finalize removes libcrypto drag-in"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'libudev-tinfoil-inactive-shim\.so\.1' "initrd finalize removes stale inactive libudev shim"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'keep_initrd_program' "initrd finalize uses explicit program allowlist"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/bin/bash' "initrd finalize removes bash"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'libsystemd\.so\.0\.\*' "initrd finalize removes real libsystemd shared object"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/share/initramfs-tools' "initrd finalize removes initramfs-tools helper hooks"
if grep -Eq '^FinalizeScripts=' "$repo_dir/mkosi.conf"; then
    require_file_contains "$repo_dir/mkosi.conf" '^FinalizeScripts=mkosi\.finalize$' "mkosi runs finalize debloat"
else
    ok "mkosi runs default mkosi.finalize debloat script"
fi

if [ -x "$repo_dir/mkosi.finalize" ]; then
    ok "mkosi.finalize exists and is executable"
else
    fail "mkosi.finalize must exist and be executable"
fi

if [ -x "$repo_dir/mkosi.images/initrd/mkosi.finalize" ]; then
    ok "initrd mkosi.finalize exists and is executable"
else
    fail "initrd mkosi.finalize must exist and be executable"
fi

require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^WithDocs=false$' "initrd mkosi disables documentation"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^CleanPackageMetadata=true$' "initrd mkosi cleans package metadata"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+udev$' "initrd mkosi excludes udev package"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.conf" '^[[:space:]]+systemd-cryptsetup$' "initrd mkosi excludes systemd-cryptsetup"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'func findPartUUID' "compiled initrd discovers root partitions from sysfs PARTUUID"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'bounded initrd module loader' "compiled initrd exposes only the bounded initrd module loader"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'parseVeritySuperblock' "compiled initrd reads measured root metadata directly"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'dmTableLoadIOCTL' "compiled initrd creates measured root with direct device-mapper ioctls"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'ensureBlockNode\(dmRootNode' "compiled initrd creates dm nodes without udev"
require_file_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'switchRoot\("/sysroot", boot\.InitBinary\)' "compiled initrd hands off to Tinfoil PID1 by default"
require_file_contains "$repo_dir/tinfoil/internal/boot/paths.go" 'InitBinary[[:space:]]*= "/usr/bin/tinfoil-init"' "shared paths pin the Tinfoil PID1 binary location"
require_file_not_contains "$repo_dir/tinfoil/cmd/initrd/main.go" 'tinfoil-pid1' "compiled initrd has no systemd PID1 fallback selector"
require_file_not_contains "$repo_dir/tinfoil/cmd/initrd/main.go" '/usr/lib/systemd/systemd' "compiled initrd cannot hand off to systemd"
require_file_contains "$repo_dir/Makefile" 'tinfoil-init ./cmd/init' "build produces Tinfoil PID1 binary"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '--exec-service' "Tinfoil PID1 exposes hardened self-exec wrapper"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'PR_SET_NO_NEW_PRIVS' "Tinfoil PID1 can enforce no_new_privs"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'PR_CAPBSET_DROP' "Tinfoil PID1 can drop capability bounding sets"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'CAP_NET_BIND_SERVICE' "Tinfoil PID1 bounds shim to bind-service capability"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'CAP_NET_ADMIN' "Tinfoil PID1 bounds egress to net-admin capability"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'bootCtx, cancelBoot := bootContext\(parent\)' "Tinfoil PID1 routes boot deadline through an explicit selector"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '<-parent\.Done\(\)' "Tinfoil PID1 lifecycle wait is not bound to the boot deadline"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'runOneShotHardened\(bootCtx, tinfoilBootTimeout\(\), "tinfoil-boot"' "Tinfoil PID1 starts boot under no_new_privs policy"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'func tinfoilBootTimeout\(\) time\.Duration' "Tinfoil PID1 owns the debug boot timeout selector"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestTinfoilBootTimeoutAllowsDebugShellToOutliveBootTimeout' "debug tinfoil-boot timeout behavior is unit-tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestBootContextAllowsDebugShellToOutliveBootTimeout' "debug PID1 boot context timeout behavior is unit-tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'harden: shimName' "Tinfoil PID1 starts shim under service hardening policy"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'harden: egressName' "Tinfoil PID1 starts egress under service hardening policy"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestTinfoilOwnedPoliciesAreHardened' "Tinfoil PID1 hardening policy is unit-tested"
require_file_contains "$repo_dir/tinfoil/cmd/boot/firewall.go" 'boot\.InitBinary, "--exec-service", boot\.EgressServiceName' "boot-time egress refresh uses hardened PID1 wrapper"
require_file_not_contains "$repo_dir/tinfoil/cmd/boot/firewall.go" 'systemctl' "boot-time egress refresh has no systemctl fallback"
require_file_not_contains "$repo_dir/tinfoil/cmd/egress/main.go" 'NOTIFY_SOCKET|READY=1|sd_notify' "egress daemon has no systemd notify path"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '"/etc/udev"' "initrd finalize removes /etc/udev"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '"/usr/lib/udev"' "initrd finalize removes /usr/lib/udev"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-udevd\.service' "initrd finalize removes systemd-udevd service"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/network/\*\.link' "initrd finalize removes systemd link policy"
require_file_not_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'cat > "\$.*udev' "initrd finalize does not write udev rules"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" 'systemd-udev-load-credentials\.service' "initrd finalize removes udev credential loader"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/systemd-networkd' "initrd finalize removes networkd payload"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/bin/networkctl' "initrd finalize removes networkctl"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/systemd-pcrlock' "initrd finalize removes pcrlock payload"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/bin/systemd-sysext' "initrd finalize removes sysext payload"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/systemd-factory-reset' "initrd finalize removes factory reset payload"
if [ -e "$repo_dir/mkosi.images/initrd/mkosi.extra/etc/modules-load.d/tinfoil-initrd.conf" ]; then
    fail "initrd source still ships systemd modules-load policy"
else
    ok "initrd source has no systemd modules-load policy"
fi
source_initrd_systemd_policy="$(
    find "$repo_dir/mkosi.images/initrd/mkosi.extra/etc/systemd" -mindepth 1 -print -quit 2>/dev/null \
    || true
)"
if [ -n "$source_initrd_systemd_policy" ]; then
    fail "initrd source still ships systemd policy ${source_initrd_systemd_policy#$repo_dir/}"
else
    ok "initrd source ships no systemd policy or masks"
fi
require_file_not_contains "$repo_dir/tinfoil/internal/attestation/attestation.go" 'os/exec|exec\.Command|modprobe' "attestation path does not execute modprobe or any command runner"
require_file_contains "$repo_dir/tinfoil/internal/device/device.go" 'DiskBySCSISerial' "Tinfoil owns config/external disk discovery"
require_file_contains "$repo_dir/tinfoil/internal/device/device.go" 'ModelDeviceByFilesystemUUID' "Tinfoil owns modelwrap filesystem UUID discovery"
require_file_contains "$repo_dir/tinfoil/internal/device/device.go" 'ModelDeviceByPARTUUID' "Tinfoil owns EMWP PARTUUID discovery"
require_file_contains "$repo_dir/tinfoil/internal/device/device.go" 'SetupRequiredPermissions' "Tinfoil owns required device permissions"
require_file_contains "$repo_dir/tinfoil/internal/device/device.go" 'erofsFilesystemUUID' "Tinfoil owns EROFS filesystem UUID parsing"
require_file_not_contains "$repo_dir/tinfoil/internal/device/device.go" 'os/exec|exec\.Command|blkid' "modelwrap filesystem UUID discovery has no command-runner or blkid path"
require_file_contains "$repo_dir/tinfoil/internal/device/device_test.go" 'ScopesToModelwrapDisk' "modelwrap PARTUUID discovery is scoped in tests"
require_file_contains "$repo_dir/tinfoil/internal/device/device_test.go" 'TestFilesystemUUIDReadsEROFSSuperblock' "modelwrap EROFS UUID parsing is unit-tested"
source_modules_load="$(
    find "$repo_dir/mkosi.extra/etc/modules-load.d" -mindepth 1 -type f -print -quit 2>/dev/null \
    || true
)"
if [ -n "$source_modules_load" ]; then
    fail "source tree still ships rootfs modules-load policy ${source_modules_load#$repo_dir/}"
else
    ok "source tree ships no rootfs modules-load policy"
fi
source_networkd_policy="$(
    find "$repo_dir/mkosi.extra/etc/systemd/network" -mindepth 1 -print -quit 2>/dev/null \
    || true
)"
if [ -n "$source_networkd_policy" ]; then
    fail "source tree still ships systemd-networkd policy ${source_networkd_policy#$repo_dir/}"
else
    ok "source tree ships no systemd-networkd policy"
fi
if [ -e "$repo_dir/mkosi.extra/etc/systemd/network/20-enp0s2.link" ]; then
    fail "source tree must not ship net_setup_link policy"
else
    ok "source tree excludes net_setup_link policy"
fi
source_systemd_policy="$(
    find "$repo_dir/mkosi.extra/etc/systemd" -mindepth 1 \( -type f -o -type l \) -print -quit 2>/dev/null \
    || true
)"
if [ -n "$source_systemd_policy" ]; then
    fail "source tree still ships systemd policy ${source_systemd_policy#$repo_dir/}"
else
    ok "source tree ships no systemd unit or drop-in policy"
fi

for pattern in \
    '/etc/apt' \
    '/etc/dbus-1' \
    '/etc/default/dbus' \
    '/etc/dpkg' \
    '/etc/dkms' \
    '/etc/modules' \
    '/etc/modules-load.d' \
    '/etc/sysctl\.conf' \
    '/etc/sysctl\.d' \
    '/usr/lib/udev/hwdb' \
    '/usr/lib/udev/rules.d/40-vm-hotadd.rules' \
    '/usr/lib/udev/rules.d/60-persistent-storage-dm.rules' \
    '/usr/lib/udev/rules.d/60-gpiochip.rules' \
    '/usr/lib/udev/rules.d/60-infiniband.rules' \
    '/usr/lib/udev/rules.d/78-graphics-card.rules' \
    '/usr/lib/udev/rules.d/80-net-setup-link.rules' \
    '/usr/lib/udev/rules.d/81-net-dhcp.rules' \
    '/usr/lib/udev/rules.d/82-net-auto-link-local.rules' \
    '/usr/lib/udev/rules.d/90-image-dissect.rules' \
    '/etc/binfmt.d' \
    '/usr/lib/binfmt.d' \
    '/etc/systemd/network/\*\.link' \
    '/usr/lib/systemd/network/\*\.link' \
    '/usr/lib/systemd/system/breakpoint-pre-\*\.service' \
    '/usr/lib/systemd/system/bluetooth.target' \
    '/usr/lib/systemd/system/capsule@\.service' \
    '/usr/lib/systemd/system/capsule.slice' \
    '/usr/lib/systemd/system/debug-shell.service' \
    '/usr/lib/systemd/system/emergency\.\*' \
    '/usr/lib/systemd/system/getty\*\.service' \
    '/usr/lib/systemd/system/getty\*\.target' \
    '/usr/lib/systemd/system/kmod-static-nodes.service' \
    '/usr/lib/systemd/system/kmod.service' \
    '/usr/lib/systemd/system/pam_namespace.service' \
    '/usr/lib/systemd/system/printer.target' \
    '/usr/lib/systemd/system/proc-sys-fs-binfmt_misc\.\*' \
    '/usr/lib/systemd/system/procps.service' \
    '/usr/lib/systemd/system/quotaon\*' \
    '/usr/lib/systemd/system/rescue\.\*' \
    '/usr/lib/systemd/system/rpcbind.target' \
    '/usr/lib/systemd/system/smartcard.target' \
    '/usr/lib/systemd/system/sleep.target' \
    '/usr/lib/systemd/system/sound.target' \
    '/usr/lib/systemd/system/storage-target-mode.target' \
    '/usr/lib/systemd/system/sys-fs-fuse-connections.mount' \
    '/usr/lib/systemd/system/sys-kernel-debug.mount' \
    '/usr/lib/systemd/system/sys-kernel-tracing.mount' \
    '/usr/lib/systemd/system/systemd-ask-password\*' \
    '/usr/lib/systemd/system/systemd-bootctl\*' \
    '/usr/lib/systemd/system/systemd-bsod.service' \
    '/usr/lib/systemd/system/systemd-creds\*' \
    '/usr/lib/systemd/system/dbus.service' \
    '/usr/lib/systemd/system/dbus.socket' \
    '/usr/lib/systemd/system/dbus-org.freedesktop\.\*\.service' \
    '/usr/lib/systemd/system/first-boot-complete.target' \
    '/usr/lib/systemd/system/hibernate.target' \
    '/usr/lib/systemd/system/systemd-hibernate-clear.service' \
    '/usr/lib/systemd/system/systemd-journal-catalog-update.service' \
    '/usr/lib/systemd/system/systemd-journal-flush.service' \
    '/usr/lib/systemd/system/systemd-journald-audit.socket' \
    '/usr/lib/systemd/system/systemd-journald-dev-log.socket' \
    '/usr/lib/systemd/system/systemd-journald-varlink@\.socket' \
    '/usr/lib/systemd/system/systemd-logind-varlink.socket' \
    '/usr/lib/systemd/system/ldconfig.service' \
    '/usr/lib/systemd/system/systemd-loop@\.service' \
    '/usr/lib/systemd/system/systemd-machine-id-commit.service' \
    '/usr/lib/systemd/system/systemd-modules-load.service' \
    '/usr/lib/systemd/system/systemd-mute-console\*' \
    '/usr/lib/systemd/system/systemd-networkd-resolve-hook.socket' \
    '/usr/lib/systemd/system/systemd-networkd-varlink.socket' \
    '/usr/lib/systemd/system/systemd-networkd-wait-online.service' \
    '/usr/lib/systemd/system/systemd-networkd-wait-online@\.service' \
    '/usr/lib/systemd/system/systemd-random-seed.service' \
    '/usr/lib/systemd/system/systemd-resolved.service' \
    '/usr/lib/systemd/system/systemd-resolved-.*\.socket' \
    '/usr/lib/systemd/system/systemd-quotacheck\*' \
    '/usr/lib/systemd/system/systemd-rfkill\.\*' \
    '/usr/lib/systemd/system/systemd-storagetm.service' \
    '/usr/lib/systemd/system/systemd-suspend.service' \
    '/usr/lib/systemd/system/systemd-udev-load-credentials.service' \
    '/usr/lib/systemd/system/systemd-udevd-varlink.socket' \
    '/usr/lib/systemd/system/systemd-sysusers.service' \
    '/usr/lib/systemd/system/systemd-update-done.service' \
    '/usr/lib/systemd/system/systemd-validatefs@\.service' \
    '/usr/lib/systemd/system/rc-local.service' \
    '/usr/lib/systemd/system/syslog.socket' \
    '/usr/lib/systemd/system/tpm2.target' \
    '/usr/lib/systemd/system/usb-gadget.target' \
    '/usr/lib/systemd/system/user@\.service' \
    '/usr/lib/systemd/system/user@\.service.d' \
    '/usr/lib/systemd/system/user@0.service.d' \
    '/usr/lib/systemd/system/user-\.slice.d' \
    '/usr/lib/systemd/system/user-runtime-dir@\.service' \
    '/usr/lib/systemd/system/user.slice' \
    '/etc/systemd/system/systemd-hibernate.service.wants' \
    '/etc/systemd/system/systemd-suspend.service.wants' \
    '/etc/systemd/system/systemd-suspend-then-hibernate.service.wants' \
    '/etc/systemd/system/systemd-journald.service.wants/systemd-journald-audit.socket' \
    '/etc/systemd/system/systemd-journald.service.wants/systemd-journald-dev-log.socket' \
    '/usr/lib/systemd/system-generators/systemd-fstab-generator' \
    '/usr/lib/systemd/system/dbus-org.freedesktop.hostname1.service' \
    '/usr/lib/systemd/system/initrd-root-device.target.wants/remote-\*\.target' \
    '/usr/lib/systemd/system/sockets.target.wants/systemd-creds.socket' \
    '/usr/lib/systemd/system/sockets.target.wants/systemd-journald-audit.socket' \
    '/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket' \
    '/usr/lib/systemd/system/sockets.target.wants/systemd-udevd-varlink.socket' \
    '/usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-audit.socket' \
    '/usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-dev-log.socket' \
    '/usr/lib/systemd/system/sockets.target.wants/dbus.socket' \
    '/usr/lib/systemd/system/multi-user.target.wants/dbus.service' \
    '/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service' \
    '/etc/systemd/system/sockets.target.wants/systemd-journald-audit.socket' \
    '/etc/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket' \
    '/etc/systemd/system/sockets.target.wants/systemd-networkd-resolve-hook.socket' \
    '/etc/systemd/system/sockets.target.wants/systemd-networkd-varlink.socket' \
    '/etc/systemd/system/sockets.target.wants/systemd-resolved-.*\.socket' \
    '/etc/systemd/system/sockets.target.wants/systemd-udevd-varlink.socket' \
    '/etc/systemd/system/sysinit.target.wants/systemd-random-seed.service' \
    '/etc/systemd/system/sysinit.target.wants/systemd-resolved.service' \
    '/etc/systemd/system/sysinit.target.wants/systemd-modules-load.service' \
    '/etc/systemd/system/sysinit.target.wants/systemd-sysusers.service' \
    '/usr/lib/systemd/system/sysinit.target.wants/systemd-hibernate-clear.service' \
    '/usr/lib/systemd/system/sysinit.target.wants/kmod-static-nodes.service' \
    '/usr/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service' \
    '/usr/lib/systemd/system/sysinit.target.wants/systemd-pcr\*\.service' \
    '/usr/lib/systemd/system/sysinit.target.wants/systemd-random-seed.service' \
    '/usr/lib/systemd/system/sysinit.target.wants/systemd-sysusers.service' \
    '/usr/lib/systemd/system/sysinit.target.wants/systemd-tpm2-\*\.service' \
    '/etc/systemd/system/sysinit.target.wants/systemd-udev-load-credentials.service' \
    '/usr/lib/systemd/systemd-user-runtime-dir' \
    '/usr/lib/systemd/systemd-validatefs' \
    '/usr/lib/systemd/systemd-networkd-wait-online' \
    '/usr/lib/systemd/systemd-modules-load' \
    '/usr/lib/systemd/systemd-random-seed' \
    '/usr/lib/systemd/systemd-resolved' \
    '/usr/lib/systemd/resolv.conf' \
    '/usr/lib/systemd/user' \
    '/usr/lib/systemd/user-generators' \
    '/usr/bin/dbus-daemon' \
    '/usr/bin/hostnamectl' \
    '/usr/bin/networkctl' \
    '/usr/bin/systemd-sysusers' \
    '/usr/lib/dbus-1.0' \
    '/usr/lib/sysusers.d/dbus.conf' \
    '/usr/lib/sysusers.d' \
    '/usr/lib/sysctl.d' \
    '/usr/lib/tmpfiles.d' \
    '/usr/lib/modules-load.d' \
    '/usr/share/dbus-1' \
    '/etc/systemd/resolved.conf' \
    '/usr/lib/systemd/resolved.conf.d' \
    '/usr/include' \
    '/usr/share/doc' \
    '/usr/share/dpkg' \
    '/usr/share/perl' \
    '/usr/share/perl5' \
    '/usr/lib/x86_64-linux-gnu/perl' \
    '/usr/lib/x86_64-linux-gnu/perl-base' \
    '/usr/lib/firmware' \
    '/usr/src/linux-headers-\*' \
    '/usr/src/nvidia-\*' \
    '/var/lib/dkms' \
    '/usr/bin/gcc' \
    '/usr/bin/g\+\+' \
    '/usr/bin/make' \
    '/usr/bin/patch' \
    '/usr/bin/systemd-ask-password' \
    '/usr/bin/systemd-creds' \
    '/usr/bin/systemd-mute-console' \
    '/usr/bin/systemd-tty-ask-password-agent' \
    '/usr/sbin/agetty' \
    '/usr/sbin/dkms' \
    '/usr/sbin/getty' \
    '/usr/sbin/pam_namespace_helper' \
    '/usr/sbin/sysctl' \
    '/usr/lib/x86_64-linux-gnu/security/pam_namespace\.so' \
    '/var/lib/dbus' \
    '/var/lib/systemd/random-seed' \
    '/var/lib/systemd/deb-systemd-helper-enabled'; do
    require_file_contains "$repo_dir/mkosi.finalize" "$pattern" "finalize removes $pattern"
done
require_file_contains "$repo_dir/mkosi.finalize" 'containerd\.service' "finalize edits containerd unit"
require_file_contains "$repo_dir/mkosi.finalize" 'dbus\\\.service' "finalize removes containerd dbus ordering"
require_file_contains "$repo_dir/tinfoil/internal/boot/state.go" 'StageNetwork[[:space:]]*=[[:space:]]*"network"' "boot state tracks network readiness"
require_file_contains "$repo_dir/tinfoil/cmd/boot/main.go" 'waitForNetworkReady' "tinfoil-boot owns network readiness"
require_file_order "$repo_dir/tinfoil/cmd/boot/main.go" 'waitForNetworkReady' 'verifyGPUAttestation' "tinfoil-boot waits for network before GPU attestation"
require_file_contains "$repo_dir/tinfoil/internal/boot/state_test.go" 'TestInitialStagesNetworkBeforeGPUAttestation' "boot stage order keeps network before GPU attestation"
require_file_contains "$repo_dir/tinfoil/cmd/boot/network_ready.go" '/proc/net/route' "network readiness checks kernel route table"
require_file_contains "$repo_dir/tinfoil/cmd/boot/network_ready.go" '/etc/resolv.conf' "network readiness checks resolver config"
require_file_contains "$repo_dir/tinfoil/cmd/boot/network_ready.go" 'boot\.IPBinary, "link", "set", "dev"' "Tinfoil activates kernel Ethernet links without udev"
require_file_contains "$repo_dir/tinfoil/cmd/boot/network_ready.go" 'requestDHCPv4Lease' "Tinfoil owns DHCPv4 lease acquisition without udev"
require_file_contains "$repo_dir/tinfoil/cmd/boot/network_ready.go" 'syscall\.AF_PACKET' "Tinfoil DHCPv4 uses raw Ethernet frames without networkd"
require_file_contains "$repo_dir/tinfoil/cmd/boot/network_ready.go" 'boot\.IPBinary, "addr", "replace"' "Tinfoil applies DHCPv4 addresses explicitly"
require_file_contains "$repo_dir/tinfoil/cmd/boot/network_ready.go" 'boot\.IPBinary, "route", "replace", "default"' "Tinfoil applies the DHCPv4 default route explicitly"
require_file_contains "$repo_dir/tinfoil/cmd/boot/main.go" 'maybeDropToDebugFailureShell\(err\)' "tinfoil-boot has a debug-only failure shell hook for serial GPU debugging"
require_file_contains "$repo_dir/tinfoil/cmd/boot/debug_shell.go" 'tinfoil-debug=on' "boot failure shell is gated on the debug cmdline flag"
require_file_contains "$repo_dir/tinfoil/cmd/boot/debug_shell.go" 'debugFailureConsolePath = "/dev/console"' "boot failure shell attaches to the serial console device"
require_file_contains "$repo_dir/tinfoil/cmd/boot/debug_shell.go" 'debugFailureShellPath[[:space:]]+= "/bin/sh"' "boot failure shell uses the minimal POSIX shell"
require_file_contains "$repo_dir/tinfoil/cmd/boot/debug_shell.go" 'Pdeathsig:[[:space:]]+syscall\.SIGKILL' "boot failure shell dies if the debug tinfoil-boot parent is killed"
require_file_contains "$repo_dir/tinfoil/cmd/boot/debug_shell_test.go" 'TestDebugFailureShellEnabledRequiresExactDebugFlag' "boot failure shell debug flag gate is tested"
require_file_contains "$repo_dir/tinfoil/cmd/boot/debug_shell_test.go" 'TestMaybeDropToDebugFailureShellSkipsWithoutDebugFlag' "boot failure shell is tested disabled without debug flag"
require_file_not_contains "$repo_dir/mkosi.finalize" 'default\.target' "finalize does not recreate a systemd default target"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'name:[[:space:]]*"containerd"' "Tinfoil PID1 starts containerd directly"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'name:[[:space:]]*"dockerd"' "Tinfoil PID1 starts dockerd directly"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'loadDockerKernelModules\(\)' "Tinfoil PID1 owns Docker runtime module loading"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'unix\.FinitModule' "Tinfoil PID1 uses direct finit_module for Docker runtime modules"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'MODULE_INIT_COMPRESSED_FILE' "Tinfoil PID1 can load compressed Docker runtime modules without kmod"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/fs/overlayfs/overlay\.ko\.zst' "Tinfoil PID1 bounds Docker overlay module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/sched/sch_fq_codel\.ko\.zst' "Tinfoil PID1 bounds Docker default qdisc module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/drivers/net/veth\.ko\.zst' "Tinfoil PID1 bounds Docker veth module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/llc/llc\.ko\.zst' "Tinfoil PID1 bounds Docker bridge dependency llc"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/802/stp\.ko\.zst' "Tinfoil PID1 bounds Docker bridge dependency stp"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/bridge/bridge\.ko\.zst' "Tinfoil PID1 bounds Docker bridge dependency bridge"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/bridge/br_netfilter\.ko\.zst' "Tinfoil PID1 bounds Docker bridge netfilter module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nf_tables\.ko\.zst' "Tinfoil PID1 bounds nftables module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nft_ct\.ko\.zst' "Tinfoil PID1 bounds nft conntrack module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nft_chain_nat\.ko\.zst' "Tinfoil PID1 bounds nft NAT chain module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nft_compat\.ko\.zst' "Tinfoil PID1 bounds nft xtables compatibility module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nfnetlink\.ko\.zst' "Tinfoil PID1 bounds nfnetlink module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/ipv4/netfilter/nf_defrag_ipv4\.ko\.zst' "Tinfoil PID1 bounds IPv4 conntrack defrag module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/ipv6/netfilter/nf_defrag_ipv6\.ko\.zst' "Tinfoil PID1 bounds IPv6 conntrack defrag module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nf_conntrack\.ko\.zst' "Tinfoil PID1 bounds conntrack module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nf_conntrack_netlink\.ko\.zst' "Tinfoil PID1 bounds conntrack netlink module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/nf_nat\.ko\.zst' "Tinfoil PID1 bounds netfilter NAT module path"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'ip_set\.ko' "Tinfoil PID1 does not load ipset (no consumer: nftables uses native sets)"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/x_tables\.ko\.zst' "Tinfoil PID1 bounds xtables module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/xt_MASQUERADE\.ko\.zst' "Tinfoil PID1 bounds xt MASQUERADE module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/xt_addrtype\.ko\.zst' "Tinfoil PID1 bounds xt addrtype module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/xt_conntrack\.ko\.zst' "Tinfoil PID1 bounds xt conntrack module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/xt_nat\.ko\.zst' "Tinfoil PID1 bounds xt nat module path"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'xt_set\.ko' "Tinfoil PID1 does not load xt_set (no consumer: nftables uses native sets)"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/net/netfilter/xt_tcpudp\.ko\.zst' "Tinfoil PID1 bounds xt tcpudp module path"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'loadDockerKernelModules\(\)' '"/usr/sbin/nft", "-f", "/etc/nftables\.conf"' "Tinfoil PID1 loads Docker/nft modules before applying nftables"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/arch/x86/crypto/aesni-intel\.ko\.zst' "Tinfoil PID1 bounds the NVIDIA B300 AESNI prerequisite module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'nvidiaKernelModuleParams' "Tinfoil PID1 owns NVIDIA module parameters without modprobe"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'NVreg_TemporaryFilePath=/var/tmp' "Tinfoil PID1 passes NVIDIA temporary state parameter directly"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'NVreg_EnableS0ixPowerManagement=1' "Tinfoil PID1 passes NVIDIA S0ix parameter directly"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'NVreg_PreserveVideoMemoryAllocations=1' "Tinfoil PID1 passes NVIDIA preserve-video-memory parameter directly"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/crypto/ecdsa_generic\.ko\.zst' "Tinfoil PID1 bounds NVIDIA ECDSA prerequisite module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/crypto/ecdh_generic\.ko\.zst' "Tinfoil PID1 pins the NVIDIA CC SPDM ECDH dependency (builtin on stock kernel)"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'updates/dkms/nvidia\.ko' "Tinfoil PID1 bounds NVIDIA core module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'updates/dkms/nvidia-uvm\.ko' "Tinfoil PID1 bounds NVIDIA UVM module path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/drivers/platform/wmi/wmi\.ko\.zst' "Tinfoil PID1 bounds NVIDIA modeset WMI dependency path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'kernel/drivers/acpi/video\.ko\.zst' "Tinfoil PID1 bounds NVIDIA modeset video dependency path"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'updates/dkms/nvidia-modeset\.ko' "Tinfoil PID1 bounds NVIDIA modeset module path"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'ghash-clmulni-intel' "Tinfoil PID1 does not load unneeded GHASH for the B300 first-open path"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/modules.go" 'nvidia-drm' "Tinfoil PID1 does not load NVIDIA DRM for the one-GPU compute path"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" '/sbin/modprobe|modprobe",' "Tinfoil PID1 no longer shells out to modprobe"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules_test.go" 'TestLoadDockerKernelModulesLoadsFixedClosure' "Docker runtime module closure order is tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules_test.go" 'TestLoadNVIDIAPrerequisiteKernelModulesLoadsAESNI' "NVIDIA AESNI prerequisite module closure is tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules_test.go" 'TestLoadNVIDIACoreKernelModulesLoadsFixedClosureWithParams' "NVIDIA core module closure and params are tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules_test.go" 'TestLoadNVIDIAUVMKernelModulesLoadsOnlyMissingUVMWhenCoreLoaded' "NVIDIA UVM module closure is tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules_test.go" 'TestLoadNVIDIAModesetKernelModulesLoadsFixedClosure' "NVIDIA modeset module closure is tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/modules_test.go" 'RejectsBroadModuleCandidate' "Docker runtime module loader rejects broad module paths"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'startOptionalNVIDIA\(bootCtx\)' "Tinfoil PID1 owns optional NVIDIA startup"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'startOptionalSyslogSink\(superviseCtx\)' "Tinfoil PID1 starts the syslog sink independently of GPU presence"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'cancelSupervise\(\)' "Tinfoil PID1 stops service supervision on boot failure (fail-closed)"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'hasNVIDIAPCIDevice' "Tinfoil PID1 gates NVIDIA startup on sysfs PCI evidence"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaPCIDevices' "Tinfoil PID1 can enumerate NVIDIA PCI devices without udev"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestHasNVIDIAPCIDevice' "NVIDIA PCI sysfs discovery is unit tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaMinProbeUptime[[:space:]]*= 17 \* time\.Second' "Tinfoil PID1 uses a bounded NVIDIA pre-probe uptime gate"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'procUptimePath[[:space:]]*= "/proc/uptime"' "Tinfoil PID1 reads kernel uptime directly for the NVIDIA pre-probe gate"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'waitForNVIDIAPreProbeUptime\(ctx\)' "Tinfoil PID1 waits until stock-like uptime before probing B300 GPUs"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'waitForNVIDIAPreProbeUptime\(ctx\)' 'holdNVIDIAPCIEnableReference\(\)' "Tinfoil PID1 delays NVIDIA PCI enable until after the pre-probe uptime gate"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'waitForNVIDIAPreProbeUptime\(ctx\)' 'loadNVIDIACoreKernelModules\(\)' "Tinfoil PID1 delays NVIDIA module load until after the pre-probe uptime gate"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'holdNVIDIAPCIEnableReference' "Tinfoil PID1 owns NVIDIA PCI enable reference policy without udev"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '\[\]byte\("1\\n"\)' "Tinfoil PID1 can take a bounded NVIDIA PCI enable reference before driver probe"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'holdNVIDIAPCIEnableReference\(\)' 'loadNVIDIACoreKernelModules\(\)' "Tinfoil PID1 takes NVIDIA PCI enable reference before NVIDIA driver probe"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'pciCommandINTxDisable' "Tinfoil PID1 passively decodes NVIDIA PCI INTx state for diagnostics"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" 'disableNVIDIAPCIINTxInterrupts|setPCICommandBit|WriteAt\(buf, pciCommandOffset\)' "Tinfoil PID1 does not mutate NVIDIA PCI INTx state"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestDisableNVIDIAPCIINTxInterruptsScopesToGPUFunctions' "removed negative NVIDIA PCI INTx experiment stays out of tests"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'enableNVIDIARuntimePowerManagement' "Tinfoil PID1 owns NVIDIA PCI runtime PM policy without udev"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '\[\]byte\("auto\\n"\)' "Tinfoil PID1 mirrors stock NVIDIA bind rule by setting runtime power control to auto"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" '\[\]byte\("on\\n"\)' "Tinfoil PID1 does not force NVIDIA PCI runtime power away from stock policy"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'holdNVIDIAPCIEnableReference\(\)' 'enableNVIDIARuntimePowerManagement\(\)' "Tinfoil PID1 takes the NVIDIA PCI enable reference before applying runtime PM"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'enableNVIDIARuntimePowerManagement\(\)' 'loadNVIDIACoreKernelModules\(\)' "Tinfoil PID1 applies NVIDIA runtime PM before the driver probe"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'loadNVIDIAPrerequisiteKernelModules\(\)' "Tinfoil PID1 loads bounded NVIDIA prerequisite modules before the driver"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'loadNVIDIAPrerequisiteKernelModules\(\)' 'loadNVIDIACoreKernelModules\(\)' "Tinfoil PID1 loads AESNI before the NVIDIA driver first-open path"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'loadNVIDIACoreKernelModules\(\)' "Tinfoil PID1 explicitly loads NVIDIA core modules without udev or modprobe"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'loadNVIDIAUVMKernelModules\(\)' "Tinfoil PID1 explicitly loads NVIDIA UVM without udev or modprobe"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'loadNVIDIAModesetKernelModules\(\)' "Tinfoil PID1 explicitly loads NVIDIA modeset without udev or modprobe"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'loadNVIDIAUVMKernelModules\(\)' 'startNVIDIAPersistenced\(ctx\)' "Tinfoil PID1 mirrors stock persistenced order by loading NVIDIA UVM before the first RM open"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'startNVIDIAPersistenced\(ctx\)' 'loadNVIDIAModesetKernelModules\(\)' "Tinfoil PID1 defers NVIDIA modeset until after nvidia-persistenced first RM open"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaCoreModuleWait[[:space:]]*= 4 \* time\.Second' "Tinfoil PID1 uses a bounded NVIDIA core-module settle window"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'waitForNVIDIACoreModuleSettle\(ctx\)' "Tinfoil PID1 waits after NVIDIA core module before modeset/uvm"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'loadNVIDIACoreKernelModules\(\)' 'waitForNVIDIACoreModuleSettle\(ctx\)' "Tinfoil PID1 waits after NVIDIA core module load"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'waitForNVIDIACoreModuleSettle\(ctx\)' 'loadNVIDIAUVMKernelModules\(\)' "Tinfoil PID1 waits before loading NVIDIA UVM"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaPreRMOpenWait[[:space:]]*= 5 \* time\.Second' "Tinfoil PID1 uses a bounded NVIDIA pre-RM-open settle window"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'logNVIDIAPreRMOpenDiagnostics\("before-settle"\)' "Tinfoil PID1 records NVIDIA pre-RM-open diagnostics before settle"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'logNVIDIAPreRMOpenDiagnostics\("after-settle"\)' "Tinfoil PID1 records NVIDIA pre-RM-open diagnostics after settle"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'waitForNVIDIAPreRMOpenSettle\(ctx\)' 'startNVIDIAPersistenced\(ctx\)' "Tinfoil PID1 waits for NVIDIA driver settle before nvidia-persistenced first RM open"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" 'probeNVIDIAFirstRMOpen' "Tinfoil PID1 no longer performs an open-only NVIDIA RM probe before nvidia-persistenced"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" 'probeNVIDIADeviceOpen' "Tinfoil PID1 does not run the removed open-only NVIDIA RM probe"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'logNVIDIAPCIConfig' "Tinfoil PID1 captures NVIDIA PCI config state around RM-open probes"
require_file_order "$repo_dir/tinfoil/cmd/init/main.go" 'logNVIDIAPreRMOpenDiagnostics\("after-settle"\)' 'startNVIDIAPersistenced\(ctx\)' "Tinfoil PID1 starts nvidia-persistenced only after settle diagnostics"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'driver state not ready after module bootstrap' "Tinfoil PID1 checks NVIDIA driver state after bounded module bootstrap"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaDeviceMinors' "Tinfoil PID1 discovers NVIDIA GPU minors from driver procfs"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaCapabilityFiles' "Tinfoil PID1 discovers NVIDIA capability procfs files"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidia-modprobe' "Tinfoil PID1 does not delegate NVIDIA device setup to nvidia-modprobe"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'ensureNVIDIADeviceNodes' "Tinfoil PID1 owns NVIDIA device-node creation"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'ensureDevCharSymlink' "Tinfoil PID1 owns NVIDIA /dev/char compatibility links without udev"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'charDeviceMajors' "Tinfoil PID1 discovers NVIDIA character majors from /proc/devices"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'procDevicesPath' "Tinfoil PID1 has an explicit /proc/devices dependency for NVIDIA node creation"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'unix\.Mknod' "Tinfoil PID1 creates NVIDIA character nodes directly"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidia-caps' "Tinfoil PID1 creates NVIDIA capability nodes explicitly"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidia%d' "Tinfoil PID1 creates explicit /dev/nvidiaN nodes without udev"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiactl' "Tinfoil PID1 creates explicit /dev/nvidiactl without udev"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '0666' "Tinfoil PID1 gives NVIDIA control/GPU/UVM nodes stock-compatible permissions"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'allowedNVIDIACapabilityPath' "Tinfoil PID1 allowlists NVIDIA capability nodes"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '"mig/config", "mig/monitor"' "Tinfoil PID1 only materializes stock MIG capability nodes"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'fabric-imex-mgmt' "NVIDIA fabric capability omission is unit-tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'DeviceFileMinor' "Tinfoil PID1 only treats NVIDIA capability files with device minors as nodes"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'DeviceFileMode' "Tinfoil PID1 applies NVIDIA capability node modes from driver procfs"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'startNVIDIAPersistenced' "Tinfoil PID1 treats nvidia-persistenced as a bounded forking helper"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'prepareNVIDIAPersistencedRuntime' "Tinfoil PID1 owns nvidia-persistenced runtime directory setup"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaPersistencedSocket' "Tinfoil PID1 waits for the NVIDIA persistence socket"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'ListenUnixgram\("unixgram"' "Tinfoil PID1 provides a bounded local syslog sink for NVIDIA helper diagnostics"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" 'systemd-journald|rsyslog|syslogd' "Tinfoil PID1 syslog compatibility does not reintroduce a generic logging daemon"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'waitForNVIDIANVML' "Tinfoil PID1 waits for NVML enumeration before GPU attestation"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'hasNVIDIANVSwitch' "Tinfoil PID1 gates Fabric Manager on explicit NVSwitch discovery"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestHasNVIDIANVSwitchRequiresNVIDIASwitchClass' "NVIDIA NVSwitch sysfs discovery is unit tested"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'logNVIDIADebugDiagnostics' "Tinfoil PID1 can emit debug-only NVIDIA state before GPU probes"
require_file_not_contains "$repo_dir/tinfoil/cmd/init/main.go" 'name:[[:space:]]*"nvidia-persistenced"' "Tinfoil PID1 does not supervise nvidia-persistenced as a foreground service"
require_path_absent "$repo_dir/debug/nvidia-rm-trace.c" "NVIDIA RM LD_PRELOAD trace helper source is not part of production TCB"
require_file_not_contains "$repo_dir/Makefile" '^nvidia-rm-trace:' "build has no NVIDIA RM trace helper target"
require_file_not_contains "$repo_dir/Makefile" 'debug/nvidia-rm-trace\.c' "build does not compile a NVIDIA RM LD_PRELOAD trace helper"
require_file_contains "$repo_dir/Makefile" 'rm -f mkosi\.extra/usr/lib/tinfoil/nvidia-rm-trace\.so' "rebuild prunes stale staged NVIDIA RM trace helper artifacts"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'nvidiaRMTraceEnabled' "Tinfoil PID1 owns the NVIDIA RM trace enablement gate"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'if !bootDebugEnabled\(\)' "NVIDIA RM trace helper is gated by explicit debug mode"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'os\.Stat\(nvidiaRMTraceLibrary\)' "NVIDIA RM trace helper is gated by the installed preload library"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'LD_PRELOAD=' "Tinfoil PID1 injects the NVIDIA RM trace helper without a generic tracer"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'TINFOIL_NVIDIA_RM_TRACE_LOG' "Tinfoil PID1 passes a fixed NVIDIA RM trace log path"
require_file_contains "$repo_dir/tinfoil/cmd/init/main_test.go" 'TestNVIDIARMTraceEnabledRequiresDebugAndLibrary' "NVIDIA RM trace debug gate is unit-tested"
require_file_contains "$repo_dir/mkosi.extra/etc/modprobe.d/nvidia-lkca.conf" 'NVreg_TemporaryFilePath=/var/tmp' "Tinfoil NVIDIA parameter note keeps stock-compatible temporary driver state on tmpfs-backed /var/tmp"
require_file_contains "$repo_dir/mkosi.extra/etc/modprobe.d/nvidia-lkca.conf" 'NVreg_EnableS0ixPowerManagement=1' "Tinfoil NVIDIA parameter note keeps stock-compatible S0ix setting for B300 full-CC NVML"
require_file_contains "$repo_dir/mkosi.extra/etc/modprobe.d/nvidia-lkca.conf" 'NVreg_PreserveVideoMemoryAllocations=1' "Tinfoil NVIDIA parameter note keeps stock-compatible preserve-video-memory setting for B300 full-CC NVML"
require_file_not_contains "$repo_dir/mkosi.extra/etc/modprobe.d/nvidia-lkca.conf" '^(install|remove)[[:space:]]' "Tinfoil NVIDIA parameter note has no modprobe install/remove hook"
require_file_contains "$repo_dir/mkosi.finalize" 'nvidia_container_config=' "finalize edits NVIDIA container runtime config"
require_file_contains "$repo_dir/mkosi.finalize" 'load-kmods = false' "finalize disables NVIDIA container runtime module loading"
require_file_contains "$repo_dir/mkosi.finalize" 'runtime_kmod_loader_paths=' "finalize removes rootfs module load/unload entrypoints after depmod"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/lsmod' "finalize removes rootfs /usr/bin kmod applet entrypoints"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/kmod' "finalize removes rootfs /usr/bin kmod multicall entrypoint"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/modinfo' "finalize removes rootfs /usr/sbin modinfo entrypoint"
require_file_contains "$repo_dir/mkosi.finalize" 'libkmod\.so\.\*' "finalize removes rootfs libkmod after depmod"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/lsmod' "finalize removes rootfs /usr/sbin kmod applet entrypoints"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/modprobe' "finalize removes rootfs /usr/bin modprobe"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/modprobe' "finalize removes rootfs /usr/sbin modprobe"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/insmod' "finalize removes rootfs /usr/bin insmod"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/insmod' "finalize removes rootfs /usr/sbin insmod"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/rmmod' "finalize removes rootfs /usr/bin rmmod"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/rmmod' "finalize removes rootfs /usr/sbin rmmod"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/blkid' "finalize removes rootfs blkid probing CLI"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/cryptsetup' "finalize removes rootfs cryptsetup CLI"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/dmsetup' "finalize removes rootfs dmsetup admin CLI"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/dmstats' "finalize removes rootfs dmstats admin CLI"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/sbin/veritysetup' "finalize removes rootfs veritysetup CLI"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/mount' "finalize removes rootfs mount CLI"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/bin/umount' "finalize removes rootfs umount CLI"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '"tmpfs", "/var/tmp", "tmpfs"' "Tinfoil PID1 mounts /var/tmp as tmpfs before NVIDIA driver load"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" '"tmpfs", "/dev/shm", "tmpfs"' "Tinfoil PID1 mounts POSIX shared memory tmpfs without systemd-tmpfiles"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'ensureSymlink\("/dev/shm", "/run/shm"\)' "Tinfoil PID1 owns the /run/shm compatibility symlink without systemd-tmpfiles"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'applyRuntimeResourceLimits' "Tinfoil PID1 owns runtime resource limits without systemd defaults"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'unix\.RLIMIT_NOFILE' "Tinfoil PID1 raises the nofile limit for NVIDIA and container runtime compatibility"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'unix\.RLIMIT_MEMLOCK' "Tinfoil PID1 raises the memlock limit for NVIDIA full-CC compatibility"
require_file_contains "$repo_dir/mkosi.finalize" 'install -d -m 1777 "\$BUILDROOT/var/tmp"' "build creates an explicit /var/tmp NVIDIA state mountpoint"
require_file_contains "$repo_dir/mkosi.finalize" 'nvidia_driver_modprobe_conf=' "finalize edits stock NVIDIA modprobe policy"
require_file_contains "$repo_dir/mkosi.finalize" 'NVreg_TemporaryFilePath=' "finalize removes duplicate stock NVIDIA module policy"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/cargo/bin/coreutils' "finalize preserves rust-coreutils runtime backend"
require_file_contains "$repo_dir/mkosi.finalize" 'docker_unit="\$BUILDROOT/usr/lib/systemd/system/docker\.service"' "finalize edits Docker unit"
require_file_contains "$repo_dir/mkosi.finalize" '\^After=/ s/\[\[:space:\]\]\*network-online\\\.target' "finalize removes Docker network-online ordering"
require_file_contains "$repo_dir/mkosi.finalize" 'fabricmanager_unit="\$BUILDROOT/usr/lib/systemd/system/nvidia-fabricmanager\.service"' "finalize edits fabricmanager unit"
require_file_contains "$repo_dir/mkosi.finalize" '\^Requires=/ s/\[\[:space:\]\]\*network-online\\\.target' "finalize removes fabricmanager network-online requirement"
require_file_contains "$repo_dir/mkosi.finalize" '"/etc/udev"' "finalize removes rootfs /etc/udev"
require_file_contains "$repo_dir/mkosi.finalize" '"/usr/lib/udev"' "finalize removes rootfs /usr/lib/udev"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-udevd\.service' "finalize removes rootfs systemd-udevd service"
require_file_not_contains "$repo_dir/mkosi.finalize" 'cat > "\$.*udev' "finalize does not write rootfs udev rules"
require_file_contains "$repo_dir/mkosi.finalize" 'systemd-udev-load-credentials' "finalize removes udev credential loader"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/system/initrd-\*' "finalize removes stale rootfs initrd unit graph"
require_file_contains "$repo_dir/mkosi.finalize" 'ensure_static_group render 107' "finalize installs static render group"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/system/systemd-pcrextend\*' "finalize removes pcrextend unit payload"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/system/systemd-sysext\*' "finalize removes sysext unit payload"
require_file_contains "$repo_dir/mkosi.finalize" '/etc/systemd/system/factory-reset.target.wants' "finalize removes factory reset wants directory"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/system/factory-reset.target' "finalize removes factory reset targets"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/systemd-network-generator' "finalize removes network generator binary"
require_file_contains "$repo_dir/mkosi.finalize" '/etc/systemd/system/sysinit.target.wants/systemd-network-generator.service' "finalize removes network generator wants link"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/system-generators/systemd-fstab-generator' "finalize removes rootfs fstab generator"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/system/timers.target.wants/\*' "finalize removes stale vendor timer wants"
require_file_contains "$repo_dir/mkosi.finalize" '/etc/modules-load\.d' "finalize removes rootfs modules-load config directory"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/system/systemd-modules-load\.service' "finalize removes rootfs modules-load unit"
require_file_contains "$repo_dir/mkosi.finalize" '/usr/lib/systemd/systemd-modules-load' "finalize removes rootfs modules-load helper"
require_file_contains "$repo_dir/mkosi.finalize" '\^After=/ s/\[\[:space:\]\]\*systemd-modules-load\\\.service' "finalize scrubs stale sysctl modules-load ordering"
require_file_contains "$repo_dir/mkosi.finalize" 'initrd-switch-root\\\.target' "finalize scrubs stale rootfs initrd-switch ordering"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/breakpoint-pre-\*\.service' "initrd finalize removes breakpoint shell services"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/debug-shell.service' "initrd finalize removes debug shell service"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/getty\*\.service' "initrd finalize removes getty services"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/systemd-bsod.service' "initrd finalize removes bsod service"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/bin/systemd-mute-console' "initrd finalize removes mute-console binary"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/systemd-creds\*' "initrd finalize removes credential socket units"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/systemd-rfkill\.\*' "initrd finalize removes rfkill units"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/systemd-quotacheck\*' "initrd finalize removes quota-check units"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/lib/systemd/system/sys-kernel-debug.mount' "initrd finalize removes debugfs mount"
require_file_contains "$repo_dir/mkosi.images/initrd/mkosi.finalize" '/usr/share/bash-completion' "initrd finalize removes shell completions"

if [ -f "$repo_dir/initrd.cpio.zst" ]; then
    echo "=== initrd artifact ==="
    if ! command -v zstdcat >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; then
        fail "cannot inspect initrd artifact without zstdcat and cpio"
    else
        initrd_listing="$(zstdcat "$repo_dir/initrd.cpio.zst" | cpio -it 2>/dev/null || true)"
        initrd_extract="$(mktemp -d)"
        if (cd "$initrd_extract" && zstdcat "$repo_dir/initrd.cpio.zst" | cpio -id --quiet); then
            initrd_real_libsystemd="$(
                find "$initrd_extract/usr/lib/x86_64-linux-gnu" \
                    -maxdepth 1 -type f -name 'libsystemd.so.0.*' \
                    -print -quit 2>/dev/null \
                || true
            )"
            if [ -n "$initrd_real_libsystemd" ]; then
                fail "initrd still contains real libsystemd ${initrd_real_libsystemd#"$initrd_extract"/}"
            else
                ok "initrd excludes real libsystemd shared object"
            fi

            initrd_libudev_payload="$(
                find "$initrd_extract/usr/lib/x86_64-linux-gnu" \
                    -maxdepth 1 \( -name 'libudev.so*' -o -name 'libudev-tinfoil*' \) \
                    -print -quit 2>/dev/null \
                || true
            )"
            if [ -n "$initrd_libudev_payload" ]; then
                fail "initrd still contains libudev payload ${initrd_libudev_payload#"$initrd_extract"/}"
            else
                ok "initrd excludes libudev shared objects and shims"
            fi

            initrd_libdevmapper_payload="$(
                find "$initrd_extract/usr/lib/x86_64-linux-gnu" \
                    -maxdepth 1 -name 'libdevmapper.so*' -print -quit 2>/dev/null \
                || true
            )"
            if [ -n "$initrd_libdevmapper_payload" ]; then
                fail "initrd still contains libdevmapper payload ${initrd_libdevmapper_payload#"$initrd_extract"/}"
            else
                ok "initrd excludes libdevmapper shared object"
            fi

            initrd_direct_systemd_dep="$(
                find "$initrd_extract" -type f -print0 2>/dev/null \
                | xargs -0 -r readelf -d 2>/dev/null \
                | awk '/^File:/ { file=$2 } /NEEDED/ && /libsystemd\.so/ { print file; exit }' \
                | sed "s#$initrd_extract/##" \
                || true
            )"
            if [ -n "$initrd_direct_systemd_dep" ]; then
                fail "initrd still has direct libsystemd dependency $initrd_direct_systemd_dep"
            else
                ok "initrd has no direct libsystemd dependencies"
            fi

            initrd_direct_libudev_dep="$(
                find "$initrd_extract" -type f -print0 2>/dev/null \
                | xargs -0 -r readelf -d 2>/dev/null \
                | awk '/^File:/ { file=$2 } /NEEDED/ && /libudev\.so/ { print file; exit }' \
                | sed "s#$initrd_extract/##" \
                || true
            )"
            if [ -n "$initrd_direct_libudev_dep" ]; then
                fail "initrd still has direct libudev dependency $initrd_direct_libudev_dep"
            else
                ok "initrd has no direct libudev dependencies"
            fi

            initrd_unexpected_program="$(
                for dir in "$initrd_extract/usr/bin" "$initrd_extract/usr/sbin" "$initrd_extract/bin" "$initrd_extract/sbin"; do
                    [ -d "$dir" ] || continue
                    find "$dir" -maxdepth 1 \( -type f -o -type l \) -print 2>/dev/null
                done | sort | while IFS= read -r program; do
                    rel="${program#"$initrd_extract"}"
                    case "$rel" in
                        /usr/bin/tinfoil-initrd)
                            ;;
                        *)
                            printf '%s\n' "$rel"
                            break
                            ;;
                    esac
                done
            )"
            if [ -n "$initrd_unexpected_program" ]; then
                fail "initrd program allowlist has unexpected entry $initrd_unexpected_program"
            else
                ok "initrd program entry points match the explicit boot allowlist"
            fi

            if [ -e "$initrd_extract/usr/lib/cargo/bin/coreutils" ]; then
                fail "initrd still contains coreutils backend"
            else
                ok "initrd excludes coreutils backend"
            fi

            if [ -L "$initrd_extract/init" ] && [ "$(readlink "$initrd_extract/init")" = "usr/bin/tinfoil-initrd" ]; then
                ok "initrd /init artifact points to compiled Tinfoil initrd entrypoint"
            else
                fail "initrd /init artifact is not the compiled Tinfoil initrd entrypoint"
            fi
            if grep -aq 'tinfoil-initrd-go-v6' "$initrd_extract/usr/bin/tinfoil-initrd"; then
                ok "initrd compiled entrypoint carries Tinfoil marker"
            else
                fail "initrd compiled entrypoint is missing Tinfoil marker"
            fi
            if readelf -h "$initrd_extract/usr/bin/tinfoil-initrd" >/dev/null 2>&1; then
                ok "initrd entrypoint is an ELF binary"
            else
                fail "initrd entrypoint is not an ELF binary"
            fi
            if readelf -d "$initrd_extract/usr/bin/tinfoil-initrd" 2>/dev/null | grep -q 'NEEDED'; then
                fail "initrd entrypoint has dynamic library dependencies"
            else
                ok "initrd entrypoint is static"
            fi
            if grep -aEq '/(usr/)?bin/(ba)?sh|switch_root|/usr/lib/systemd/systemd|tinfoil-pid1' "$initrd_extract/usr/bin/tinfoil-initrd"; then
                fail "initrd entrypoint still references shell, switch_root, or systemd fallback"
            else
                ok "initrd entrypoint has no shell, switch_root, or systemd fallback references"
            fi
            for key in 'bounded initrd module loader' 'initrd module loaded' 'verity signature not found' 'device-mapper table load' 'measured root device created' '/usr/bin/tinfoil-init'; do
                if grep -aFq -- "$key" "$initrd_extract/usr/bin/tinfoil-initrd"; then
                    ok "initrd entrypoint contains $key"
                else
                    fail "initrd entrypoint is missing $key"
                fi
            done
            if grep -aEq '/usr/sbin/modprobe|/usr/bin/kmod|init_module' "$initrd_extract/usr/bin/tinfoil-initrd"; then
                fail "initrd entrypoint still references broad module loader execution"
            else
                ok "initrd entrypoint has no broad module loader execution references"
            fi
            if grep -aEq '/usr/sbin/dmsetup|--noudevrules|--noudevsync|DM_DISABLE_UDEV' "$initrd_extract/usr/bin/tinfoil-initrd"; then
                fail "initrd entrypoint still references dmsetup/libdevmapper CLI activation"
            else
                ok "initrd entrypoint has no dmsetup/libdevmapper CLI activation references"
            fi
        else
            fail "cannot extract initrd artifact for ELF checks"
        fi
        rm -rf "$initrd_extract"

        for path in \
            etc/binfmt.d \
            etc/dbus-1 \
            etc/default/dbus \
            etc/modprobe.d \
            etc/modules \
            etc/modules-load.d/modules.conf \
            etc/systemd/system/emergency.service \
            etc/systemd/system/emergency.target \
            etc/systemd/system/rescue.service \
            etc/systemd/system/rescue.target \
            etc/systemd/system/sysinit.target.wants/systemd-random-seed.service \
            etc/systemd/system/sysinit.target.wants/systemd-sysusers.service \
            etc/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev-early.service \
            etc/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev.service \
            etc/systemd/user \
            etc/systemd/user/basic.target.wants/systemd-tmpfiles-setup.service \
            etc/systemd/user/timers.target.wants/systemd-tmpfiles-clean.timer \
            etc/sysctl.conf \
            etc/sysctl.d \
            etc/udev \
            etc/udev/hwdb.d \
            etc/udev/iocost.conf \
            usr/bin/dbus-daemon \
            usr/bin/hostnamectl \
            usr/bin/systemd-sysusers \
            usr/bin/systemd-creds \
            usr/bin/systemd-mute-console \
            usr/bin/udevadm \
            usr/sbin/agetty \
            usr/sbin/getty \
            usr/lib/binfmt.d \
            usr/lib/dbus-1.0 \
            usr/lib/modprobe.d \
            usr/lib/modules-load.d \
            usr/lib/systemd/system/autovt@.service \
            usr/lib/systemd/system/bluetooth.target \
            usr/lib/systemd/system/breakpoint-pre-basic.service \
            usr/lib/systemd/system/breakpoint-pre-mount.service \
            usr/lib/systemd/system/breakpoint-pre-switch-root.service \
            usr/lib/systemd/system/breakpoint-pre-udev.service \
            usr/lib/systemd/system/capsule@.service \
            usr/lib/systemd/system/capsule.slice \
            usr/lib/systemd/system/console-getty.service \
            usr/lib/systemd/system/container-getty@.service \
            usr/lib/systemd/system/debug-shell.service \
            usr/lib/systemd/system/dbus.service \
            usr/lib/systemd/system/dbus.socket \
            usr/lib/systemd/system/dbus-org.freedesktop.hostname1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.locale1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.login1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.network1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.systemd1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.timedate1.service \
            usr/lib/systemd/system/emergency.service \
            usr/lib/systemd/system/emergency.target \
            usr/lib/systemd/system/first-boot-complete.target \
            usr/lib/systemd/system/getty-pre.target \
            usr/lib/systemd/system/getty-static.service \
            usr/lib/systemd/system/getty.target \
            usr/lib/systemd/system/getty.target.wants/getty-static.service \
            usr/lib/systemd/system/getty@.service \
            usr/lib/systemd/system/hibernate.target \
            usr/lib/systemd/system/hybrid-sleep.target \
            usr/lib/systemd/system/initrd.target.wants/systemd-bsod.service \
            usr/lib/systemd/system/kmod-static-nodes.service \
            usr/lib/systemd/system/kmod.service \
            usr/lib/systemd/system/ldconfig.service \
            usr/lib/systemd/system/multi-user.target.wants/getty.target \
            usr/lib/systemd/system/multi-user.target.wants/dbus.service \
            usr/lib/systemd/system/modprobe@.service \
            usr/lib/systemd/system/pam_namespace.service \
            usr/lib/systemd/system/procps.service \
            usr/lib/systemd/system/printer.target \
            usr/lib/systemd/system/quotaon-root.service \
            usr/lib/systemd/system/quotaon@.service \
            usr/lib/systemd/system/rc-local.service \
            usr/lib/systemd/system/rc-local.service.d/debian.conf \
            usr/lib/systemd/system/rescue.service \
            usr/lib/systemd/system/rescue.target \
            usr/lib/systemd/system/rpcbind.target \
            usr/lib/systemd/system/serial-getty@.service \
            usr/lib/systemd/system/smartcard.target \
            usr/lib/systemd/system/sleep.target \
            usr/lib/systemd/system/sound.target \
            usr/lib/systemd/system/sockets.target.wants/dbus.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-journald-audit.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-mute-console.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-udevd-varlink.socket \
            usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-audit.socket \
            usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/storage-target-mode.target \
            usr/lib/systemd/system/storage-target-mode.target.wants \
            usr/lib/systemd/system/suspend.target \
            usr/lib/systemd/system/suspend-then-hibernate.target \
            usr/lib/systemd/system/sys-fs-fuse-connections.mount \
            usr/lib/systemd/system/sys-kernel-debug.mount \
            usr/lib/systemd/system/sys-kernel-tracing.mount \
            usr/lib/systemd/system/sysinit.target.wants/kmod-static-nodes.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-random-seed.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-sysctl.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-sysusers.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev-early.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev.service \
            usr/lib/systemd/system/timers.target.wants/systemd-tmpfiles-clean.timer \
            usr/lib/systemd/system/systemd-bootctl.socket \
            usr/lib/systemd/system/systemd-bootctl@.service \
            usr/lib/systemd/system/systemd-bsod.service \
            usr/lib/systemd/system/systemd-creds.socket \
            usr/lib/systemd/system/systemd-creds@.service \
            usr/lib/systemd/system/systemd-hibernate-clear.service \
            usr/lib/systemd/system/systemd-hibernate-resume.service \
            usr/lib/systemd/system/systemd-hibernate.service \
            usr/lib/systemd/system/systemd-hybrid-sleep.service \
            usr/lib/systemd/system/systemd-journal-catalog-update.service \
            usr/lib/systemd/system/systemd-journal-flush.service \
            usr/lib/systemd/system/systemd-journald-audit.socket \
            usr/lib/systemd/system/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/systemd-journald-varlink@.socket \
            usr/lib/systemd/system/systemd-logind-varlink.socket \
            usr/lib/systemd/system/systemd-loop@.service \
            usr/lib/systemd/system/systemd-machine-id-commit.service \
            usr/lib/systemd/system/systemd-mute-console.socket \
            usr/lib/systemd/system/systemd-mute-console@.service \
            usr/lib/systemd/system/systemd-networkd-wait-online.service \
            usr/lib/systemd/system/systemd-networkd-wait-online@.service \
            usr/lib/systemd/system/systemd-quotacheck-root.service \
            usr/lib/systemd/system/systemd-quotacheck@.service \
            usr/lib/systemd/system/systemd-random-seed.service \
            usr/lib/systemd/system/systemd-rfkill.service \
            usr/lib/systemd/system/systemd-rfkill.socket \
            usr/lib/systemd/system/systemd-storagetm.service \
            usr/lib/systemd/system/systemd-suspend.service \
            usr/lib/systemd/system/systemd-suspend-then-hibernate.service \
            usr/lib/systemd/system/systemd-sysctl.service \
            usr/lib/systemd/system/systemd-sysusers.service \
            usr/lib/systemd/system/systemd-tmpfiles-clean.service \
            usr/lib/systemd/system/systemd-tmpfiles-clean.timer \
            usr/lib/systemd/system/systemd-tmpfiles-setup-dev-early.service \
            usr/lib/systemd/system/systemd-tmpfiles-setup-dev.service \
            usr/lib/systemd/system/systemd-update-done.service \
            usr/lib/systemd/system/systemd-validatefs@.service \
            usr/lib/systemd/system/syslog.socket \
            usr/lib/systemd/system/tpm2.target \
            usr/lib/systemd/system/usb-gadget.target \
            usr/lib/systemd/system/user-.slice.d/10-defaults.conf \
            usr/lib/systemd/system/user-runtime-dir@.service \
            usr/lib/systemd/system/user@.service \
            usr/lib/systemd/system/user@.service.d/10-login-barrier.conf \
            usr/lib/systemd/system/user@0.service.d/10-login-barrier.conf \
            usr/lib/systemd/system/user.slice \
            usr/lib/systemd/systemd-bsod \
            usr/lib/systemd/systemd-hibernate-resume \
            usr/lib/systemd/systemd-quotacheck \
            usr/lib/systemd/systemd-random-seed \
            usr/lib/systemd/systemd-rfkill \
            usr/lib/systemd/systemd-storagetm \
            usr/lib/systemd/systemd-sysctl \
            usr/lib/systemd/system/systemd-udev-load-credentials.service \
            usr/lib/systemd/system/systemd-udev-settle.service \
            usr/lib/systemd/system/systemd-udev-trigger.service \
            usr/lib/systemd/system/systemd-udevd-control.socket \
            usr/lib/systemd/system/systemd-udevd-kernel.socket \
            usr/lib/systemd/system/systemd-udevd.service \
            usr/lib/systemd/system/systemd-udevd-varlink.socket \
            usr/lib/systemd/systemd-udevd \
            usr/lib/systemd/systemd-update-done \
            usr/lib/systemd/systemd-user-runtime-dir \
            usr/lib/systemd/systemd-validatefs \
            usr/lib/systemd/user \
            usr/lib/systemd/user/bluetooth.target \
            usr/lib/systemd/user/capsule@.target \
            usr/lib/systemd/user/printer.target \
            usr/lib/systemd/user/smartcard.target \
            usr/lib/systemd/user/sound.target \
            usr/lib/x86_64-linux-gnu/security/pam_namespace.so \
            usr/lib/sysusers.d \
            usr/lib/sysusers.d/dbus.conf \
            usr/lib/sysusers.d/basic.conf \
            usr/lib/sysusers.d/debian-udev.conf \
            usr/lib/sysusers.d/systemd-journal.conf \
            usr/lib/sysusers.d/systemd-network.conf \
            usr/lib/sysctl.d \
            usr/lib/tmpfiles.d/20-systemd-osc-context.conf \
            usr/lib/tmpfiles.d/20-systemd-shell-extra.conf \
            usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf \
            usr/lib/tmpfiles.d/20-systemd-stub.conf \
            usr/lib/tmpfiles.d/credstore.conf \
            usr/lib/tmpfiles.d/cryptsetup.conf \
            usr/lib/tmpfiles.d/debian.conf \
            usr/lib/tmpfiles.d/dbus.conf \
            usr/lib/tmpfiles.d/home.conf \
            usr/lib/tmpfiles.d/journal-nocow.conf \
            usr/lib/tmpfiles.d/legacy.conf \
            usr/lib/tmpfiles.d/libselinux1.conf \
            usr/lib/tmpfiles.d/passwd.conf \
            usr/lib/tmpfiles.d/provision.conf \
            usr/lib/tmpfiles.d/static-nodes-permissions.conf \
            usr/lib/tmpfiles.d/systemd-network.conf \
            usr/lib/tmpfiles.d/systemd-nologin.conf \
            usr/lib/tmpfiles.d/systemd-pstore.conf \
            usr/lib/tmpfiles.d/systemd-tmp.conf \
            usr/lib/tmpfiles.d/systemd.conf \
            usr/lib/tmpfiles.d/tmp.conf \
            usr/lib/tmpfiles.d/var.conf \
            usr/lib/tmpfiles.d/x11.conf \
            usr/share/dbus-1 \
            usr/share/initramfs-tools \
            usr/share/initramfs-tools/hooks/kmod \
            usr/share/initramfs-tools/hooks/dmsetup \
            usr/sbin/pam_namespace_helper \
            usr/sbin/sysctl \
            var/lib/systemd/random-seed \
            var/lib/dbus \
            usr/lib/udev/ata_id \
            usr/lib/udev/cdrom_id \
            usr/lib/udev/dmi_memory_id \
            usr/lib/udev/fido_id \
            usr/lib/udev/hwdb.bin \
            usr/lib/udev/hwdb.d \
            usr/lib/udev/iocost \
            usr/lib/udev/iocost.conf \
            usr/lib/udev/mtd_probe \
            usr/lib/udev/v4l_id \
            usr/lib/udev/rules.d/40-vm-hotadd.rules \
            usr/lib/udev/rules.d/50-firmware.rules \
            usr/lib/udev/rules.d/60-dmi-id.rules \
            usr/lib/udev/rules.d/60-drm.rules \
            usr/lib/udev/rules.d/80-drivers.rules \
            usr/lib/udev/rules.d/80-net-setup-link.rules \
            usr/lib/udev/rules.d/90-image-dissect.rules; do
            if grep -Fxq -- "$path" <<<"$initrd_listing"; then
                fail "initrd still contains /$path"
            else
                ok "initrd excludes /$path"
            fi
        done

        initrd_udev_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '^(etc/udev|usr/lib/udev|run/udev)(/|$)|(^|/)(udevadm|systemd-udev|systemd-udevd)(/|$|[.@-])' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_udev_payload" ]; then
            fail "initrd still contains udev payload /$initrd_udev_payload"
        else
            ok "initrd contains no udev daemon, rules, hwdb, helpers, sockets, or runtime db"
        fi

        initrd_modules_load_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '^(etc|usr/lib)/modules-load\.d(/|$)|(^|/)systemd-modules-load($|[.@/])' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_modules_load_payload" ]; then
            fail "initrd still contains systemd modules-load payload /$initrd_modules_load_payload"
        else
            ok "initrd has no systemd modules-load payload"
        fi

        for path in usr/bin/tinfoil-initrd; do
            if grep -Fxq -- "$path" <<<"$initrd_listing"; then
                ok "initrd keeps explicit no-udev boot tool /$path"
            else
                fail "initrd is missing explicit no-udev boot tool /$path"
            fi
        done
        initrd_manifest="$(
            zstdcat "$repo_dir/initrd.cpio.zst" \
            | cpio -i --quiet --to-stdout usr/lib/tinfoil/initrd-modules 2>/dev/null \
            || true
        )"
        if [ -n "$initrd_manifest" ]; then
            fail "initrd still carries legacy bounded module manifest"
        else
            ok "initrd omits legacy bounded module manifest"
        fi
        initrd_unexpected_module="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)[^/]+\.ko(\.|$)|(^|/)modules\.(alias|builtin|dep|devname|order|softdep|symbols)' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_unexpected_module" ]; then
            fail "initrd module allowlist has unexpected payload /$initrd_unexpected_module"
        else
            ok "initrd carries no kernel module payload or module metadata"
        fi
        for path in usr/bin/sh usr/bin/dash usr/bin/cat usr/bin/kmod usr/bin/mkdir usr/bin/mount usr/bin/sleep usr/bin/switch_root usr/bin/timeout usr/bin/bash usr/bin/rbash usr/sbin/dmsetup usr/sbin/modprobe usr/sbin/veritysetup etc/bash.bashrc root/.bashrc root/.bash_logout usr/share/debianutils/shells.d/bash etc/shells usr/lib/cargo/bin/coreutils usr/lib/x86_64-linux-gnu/libcrypto.so.3 usr/lib/x86_64-linux-gnu/libcryptsetup.so.12 usr/lib/x86_64-linux-gnu/libdevmapper.so.1.02.1 usr/lib/x86_64-linux-gnu/libkmod.so.2 usr/lib/x86_64-linux-gnu/libkmod.so.2.5.1; do
            if grep -Fxq -- "$path" <<<"$initrd_listing"; then
                fail "initrd still contains removed initrd payload /$path"
            else
                ok "initrd excludes removed initrd payload /$path"
            fi
        done
        initrd_dmsetup_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)(dmsetup)(/|$|[.@-])|(^|/)libdevmapper\.so' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_dmsetup_payload" ]; then
            fail "initrd still contains dmsetup/libdevmapper payload /$initrd_dmsetup_payload"
        else
            ok "initrd excludes dmsetup/libdevmapper payload"
        fi
        initrd_kmod_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)(kmod|modprobe)(/|$|[.@-])|(^|/)libkmod\.so|(^|/)libcrypto\.so' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_kmod_payload" ]; then
            fail "initrd still contains kmod/modprobe payload /$initrd_kmod_payload"
        else
            ok "initrd excludes kmod/modprobe payload"
        fi
        initrd_cryptsetup_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)(veritysetup|cryptsetup)(/|$|[.@-])|(^|/)libcryptsetup\.so' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_cryptsetup_payload" ]; then
            fail "initrd still contains cryptsetup/veritysetup payload /$initrd_cryptsetup_payload"
        else
            ok "initrd excludes cryptsetup/veritysetup payload"
        fi
        initrd_network_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)(networkctl|systemd-networkd|systemd-network-generator|systemd-networkd-wait-online|networkd\.conf|network-online\.target|network-pre\.target|network\.target)(/|$|[.@-])|systemd/network|dbus-org\.freedesktop\.network1\.service' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_network_payload" ]; then
            fail "initrd still contains network management payload /$initrd_network_payload"
        else
            ok "initrd excludes networkd/networkctl payload"
        fi

        initrd_systemd_policy_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)(pcrlock|pcrextend|pcrphase|tpm2-clear|systemd-(confext|sysext|factory-reset|pcrphase)|factory-reset)(/|$|[.@-])' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_systemd_policy_payload" ]; then
            fail "initrd still contains stock systemd policy payload /$initrd_systemd_policy_payload"
        else
            ok "initrd excludes pcrlock/factory-reset/sysext policy payload"
        fi

        initrd_interactive_recovery_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)(breakpoint-pre-|debug-shell|console-getty|container-getty|getty|serial-getty|emergency\.(service|target)|rescue\.(service|target)|systemd-bsod|systemd-mute-console|binfmt\.d)(/|$|[.@-])' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_interactive_recovery_payload" ]; then
            fail "initrd still contains interactive recovery/debug payload /$initrd_interactive_recovery_payload"
        else
            ok "initrd excludes interactive recovery/debug shell payload"
        fi

        initrd_stock_helper_payload="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '(^|/)(systemd-(bootctl|creds|hibernate|hybrid-sleep|suspend|random-seed|rfkill|quotacheck|loop|storagetm|sysctl|journal-catalog-update|journal-flush|machine-id-commit|update-done|logind-varlink|udev-load-credentials)|first-boot-complete\.target|procps\.service|sysctl(\.d)?|quotaon|sleep\.target|hibernate\.target|hybrid-sleep\.target|suspend\.target|suspend-then-hibernate\.target|storage-target-mode\.target|sys-fs-fuse-connections\.mount|sys-kernel-debug\.mount|sys-kernel-tracing\.mount|ldconfig\.service)(/|$|[.@-])' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_stock_helper_payload" ]; then
            fail "initrd still contains stock maintenance/helper payload /$initrd_stock_helper_payload"
        else
            ok "initrd excludes stock maintenance/helper payload"
        fi

        initrd_udevd_unit="$(
            zstdcat "$repo_dir/initrd.cpio.zst" \
            | cpio -i --quiet --to-stdout usr/lib/systemd/system/systemd-udevd.service 2>/dev/null \
            || true
        )"
        if printf '%s\n' "$initrd_udevd_unit" | grep -Eq '^Wants=systemd-udev-load-credentials\.service$'; then
            fail "initrd systemd-udevd still wants udev credential-loaded rules"
        else
            ok "initrd systemd-udevd does not load udev rules from credentials"
        fi
        if printf '%s\n' "$initrd_udevd_unit" | grep -Eq '^Sockets=.*systemd-udevd-varlink\.socket'; then
            fail "initrd systemd-udevd still exposes the varlink socket"
        else
            ok "initrd systemd-udevd does not expose the varlink socket"
        fi
        if printf '%s\n' "$initrd_udevd_unit" | grep -Eq '^After=.*(systemd-sysusers|systemd-hwdb-update)\.service'; then
            fail "initrd systemd-udevd still orders after removed sysusers/hwdb helpers"
        else
            ok "initrd systemd-udevd does not order after removed sysusers/hwdb helpers"
        fi

        initrd_tmpfiles_unit="$(
            zstdcat "$repo_dir/initrd.cpio.zst" \
            | cpio -i --quiet --to-stdout usr/lib/systemd/system/systemd-tmpfiles-setup.service 2>/dev/null \
            || true
        )"
        if printf '%s\n' "$initrd_tmpfiles_unit" | grep -Eq '^After=.*systemd-sysusers\.service'; then
            fail "initrd systemd-tmpfiles-setup still orders after removed sysusers"
        else
            ok "initrd systemd-tmpfiles-setup does not order after removed sysusers"
        fi
        if printf '%s\n' "$initrd_tmpfiles_unit" | grep -Eq '^(ImportCredential=|RestrictSUIDSGID=no$)'; then
            fail "initrd systemd-tmpfiles-setup still accepts credentials or relaxes SUID/SGID policy"
        else
            ok "initrd systemd-tmpfiles-setup has no credential imports or SUID/SGID relaxation"
        fi

        initrd_tmpfiles_policy="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '^(etc|usr/lib)/tmpfiles\.d/.*\.conf$' \
            | sort \
            || true
        )"
        if [ "$initrd_tmpfiles_policy" = "usr/lib/tmpfiles.d/tinfoil-runtime.conf" ]; then
            ok "initrd tmpfiles policy is limited to tinfoil-runtime.conf"
        else
            fail "initrd tmpfiles policy is not minimal: ${initrd_tmpfiles_policy:-<none>}"
        fi
        initrd_tinfoil_tmpfiles="$(
            zstdcat "$repo_dir/initrd.cpio.zst" \
            | cpio -i --quiet --to-stdout usr/lib/tmpfiles.d/tinfoil-runtime.conf 2>/dev/null \
            || true
        )"
        if printf '%s\n' "$initrd_tinfoil_tmpfiles" | grep -Fq '/run/cryptsetup'; then
            fail "initrd tmpfiles policy must not create /run/cryptsetup"
        else
            ok "initrd tmpfiles policy omits /run/cryptsetup"
        fi
        for key in \
            'd /run/lock 1777 root root -' \
            'L /run/shm - - - - /dev/shm' \
            'd /run/log/journal 2755 root systemd-journal -'; do
            if printf '%s\n' "$initrd_tinfoil_tmpfiles" | grep -Fxq "$key"; then
                ok "initrd tmpfiles policy keeps $key"
            else
                fail "initrd tmpfiles policy is missing $key"
            fi
        done
        initrd_broad_tmpfiles="$(
            printf '%s\n' "$initrd_tinfoil_tmpfiles" \
            | grep -E '(^|[[:space:]])(C!?|[aAhHrR]!?|D!|L[$+]|Z|z)[[:space:]]|/etc/|profile\.d|pstore|coredump|nologin|X11|ICE-unix|XIM-unix|font-unix|credstore|authorized_keys|tmpfiles\.\*' \
            || true
        )"
        if [ -n "$initrd_broad_tmpfiles" ]; then
            fail "initrd tmpfiles policy still contains broad distro behavior: $(printf '%s' "$initrd_broad_tmpfiles" | head -n 1)"
        else
            ok "initrd tmpfiles policy omits broad distro copy/ACL/X11/pstore behavior"
        fi

        initrd_journald_unit="$(
            zstdcat "$repo_dir/initrd.cpio.zst" \
            | cpio -i --quiet --to-stdout usr/lib/systemd/system/systemd-journald.service 2>/dev/null \
            || true
        )"
        if printf '%s\n' "$initrd_journald_unit" | grep -Eq '^(After|Sockets)=.*systemd-journald-(audit|dev-log)\.socket|^CapabilityBoundingSet=.*CAP_AUDIT_(CONTROL|READ)'; then
            fail "initrd systemd-journald still references audit/dev-log sockets or audit capabilities"
        else
            ok "initrd systemd-journald omits audit/dev-log sockets and audit capabilities"
        fi

        initrd_link_policy="$(
            printf '%s\n' "$initrd_listing" \
            | grep -E '^(etc|usr/lib)/systemd/network/.*\.link$' \
            | head -n 1 \
            || true
        )"
        if [ -n "$initrd_link_policy" ]; then
            fail "initrd still contains systemd link policy /$initrd_link_policy"
        else
            ok "initrd excludes systemd link policy"
        fi

    fi
else
    ok "initrd artifact not present yet; skipping built-initrd checks"
fi

echo "=== service hardening ==="
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'egressName:[[:space:]]*\{noNewPrivileges: true, boundCaps: \[\]int\{unix\.CAP_NET_ADMIN\}\}' "tinfoil-egress has Tinfoil-owned no_new_privs and CAP_NET_ADMIN bound"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'shimName:[[:space:]]*\{noNewPrivileges: true, boundCaps: \[\]int\{unix\.CAP_NET_BIND_SERVICE\}\}' "tinfoil-shim has Tinfoil-owned no_new_privs and CAP_NET_BIND_SERVICE bound"
require_file_contains "$repo_dir/tinfoil/cmd/init/main.go" 'containerStatusName:[[:space:]]*\{noNewPrivileges: true, boundCaps: \[\]int\{\}\}' "tinfoil-container-status has Tinfoil-owned no_new_privs and empty cap bound"

if [ -n "$rootfs" ]; then
    echo "=== rootfs surface: $rootfs ==="
    if [ ! -d "$rootfs" ]; then
        fail "rootfs path does not exist: $rootfs"
    else
        if [ -f "$rootfs/usr/lib/tinfoil/nvidia-rm-trace.so" ]; then
            ok "rootfs contains bounded NVIDIA RM trace helper"
            if command -v readelf >/dev/null 2>&1; then
                rm_trace_deps="$(readelf -d "$rootfs/usr/lib/tinfoil/nvidia-rm-trace.so" 2>/dev/null || true)"
                if grep -Eq 'lib(udev|systemd|nvidia|nvml)\.so' <<<"$rm_trace_deps"; then
                    fail "NVIDIA RM trace helper links unexpected device-policy/vendor libraries"
                else
                    ok "NVIDIA RM trace helper avoids udev/systemd/NVIDIA library dependencies"
                fi
            fi
        else
            fail "rootfs is missing bounded NVIDIA RM trace helper"
        fi
        if [ -e "$rootfs/debug/nvidia-rm-trace.c" ] || [ -e "$rootfs/usr/local/src/nvidia-rm-trace.c" ]; then
            fail "rootfs contains NVIDIA RM trace build source"
        else
            ok "rootfs excludes NVIDIA RM trace build source"
        fi
        for path in \
            etc/binfmt.d \
            etc/apt \
            etc/dbus-1 \
            etc/default/dbus \
            etc/dkms \
            etc/dpkg \
            etc/modules \
            etc/modules-load.d \
	            etc/sysctl.conf \
	            etc/udev \
	            opt/tinfoil-shims \
	            etc/systemd/system/console-getty.service \
            etc/systemd/system/emergency.service \
            etc/systemd/system/emergency.target \
            etc/systemd/system/getty@.service \
            etc/systemd/system/nvidia-powerd.service \
            etc/systemd/system/rescue.service \
            etc/systemd/system/rescue.target \
            etc/systemd/system/serial-getty@.service \
            etc/systemd/system/systemd-firstboot.service \
            etc/systemd/system/systemd-logind.service \
            etc/systemd/system/systemd-logind.socket \
            etc/systemd/system/systemd-logind-varlink.socket \
            etc/systemd/system/systemd-networkd-persistent-storage.service \
            etc/systemd/system/sysinit.target.wants/systemd-random-seed.service \
            etc/systemd/system/sysinit.target.wants/systemd-resolved.service \
            etc/systemd/system/sysinit.target.wants/systemd-modules-load.service \
            etc/systemd/system/sockets.target.wants/systemd-journald-audit.socket \
            etc/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket \
            etc/systemd/system/sockets.target.wants/systemd-networkd-resolve-hook.socket \
            etc/systemd/system/sockets.target.wants/systemd-networkd-varlink.socket \
            etc/systemd/system/sockets.target.wants/systemd-resolved-monitor.socket \
            etc/systemd/system/sockets.target.wants/systemd-resolved-varlink.socket \
            etc/systemd/system/sockets.target.wants/systemd-udevd-control.socket \
            etc/systemd/system/sockets.target.wants/systemd-udevd-kernel.socket \
            etc/systemd/system/sockets.target.wants/systemd-udevd-varlink.socket \
            etc/systemd/system/sysinit.target.wants/systemd-sysusers.service \
            etc/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev-early.service \
            etc/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev.service \
            etc/systemd/resolved.conf \
            etc/systemd/system/timers.target.wants/dpkg-db-backup.timer \
            etc/systemd/system/timers.target.wants/fstrim.timer \
            etc/systemd/system/timers.target.wants/motd-news.timer \
            etc/systemd/system/dbus-org.freedesktop.hostname1.service \
            etc/systemd/system/dbus-org.freedesktop.locale1.service \
            etc/systemd/system/dbus-org.freedesktop.login1.service \
            etc/systemd/system/dbus-org.freedesktop.network1.service \
            etc/systemd/system/dbus-org.freedesktop.resolve1.service \
            etc/systemd/system/dbus-org.freedesktop.systemd1.service \
            etc/systemd/system/dbus-org.freedesktop.timedate1.service \
            etc/systemd/system/multi-user.target.wants/remote-cryptsetup.target \
            etc/systemd/system/multi-user.target.wants/remote-fs.target \
            etc/systemd/system/multi-user.target.wants/remote-integritysetup.target \
            etc/systemd/system/multi-user.target.wants/remote-veritysetup.target \
            etc/systemd/system/systemd-hibernate.service.wants \
            etc/systemd/system/systemd-journald.service.wants/systemd-journald-audit.socket \
            etc/systemd/system/systemd-journald.service.wants/systemd-journald-dev-log.socket \
            etc/systemd/system/systemd-suspend.service.wants \
            etc/systemd/system/systemd-suspend-then-hibernate.service.wants \
            etc/systemd/user \
            etc/sysctl.d/README.sysctl \
	            usr/bin/curl \
	            usr/bin/blkid \
	            usr/bin/dbus-daemon \
	            usr/bin/free \
	            usr/bin/hostnamectl \
            usr/bin/journalctl \
            usr/bin/networkctl \
            usr/bin/ping \
            usr/bin/ping4 \
            usr/bin/ping6 \
            usr/bin/systemd-ask-password \
            usr/bin/systemd-creds \
            usr/bin/systemd-mute-console \
            usr/bin/systemd-sysusers \
            usr/bin/systemd-tty-ask-password-agent \
            usr/bin/systemctl \
            usr/bin/udevadm \
            usr/bin/wcurl \
            usr/sbin/agetty \
            usr/sbin/blkid \
            usr/sbin/getty \
            usr/lib/dbus-1.0/dbus-daemon-launch-helper \
            usr/lib/dbus-1.0 \
            usr/lib/binfmt.d \
            usr/lib/systemd/system/autovt@.service \
            usr/lib/systemd/system/bluetooth.target \
            usr/lib/systemd/system/breakpoint-pre-basic.service \
            usr/lib/systemd/system/breakpoint-pre-mount.service \
            usr/lib/systemd/system/breakpoint-pre-switch-root.service \
            usr/lib/systemd/system/breakpoint-pre-udev.service \
            usr/lib/systemd/system/capsule@.service \
            usr/lib/systemd/system/capsule.slice \
            usr/lib/systemd/system/console-getty.service \
            usr/lib/systemd/system/container-getty@.service \
            usr/lib/systemd/system/debug-shell.service \
            usr/lib/systemd/system/dbus.service \
            usr/lib/systemd/system/dbus.socket \
            usr/lib/systemd/system/dbus-org.freedesktop.hostname1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.locale1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.login1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.network1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.resolve1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.systemd1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.timedate1.service \
            usr/lib/systemd/system/emergency.service \
            usr/lib/systemd/system/emergency.target \
            usr/lib/systemd/system/first-boot-complete.target \
            usr/lib/systemd/system/getty-pre.target \
            usr/lib/systemd/system/getty-static.service \
            usr/lib/systemd/system/getty.target \
            usr/lib/systemd/system/getty.target.wants/getty-static.service \
            usr/lib/systemd/system/getty@.service \
            usr/lib/systemd/system/hibernate.target \
            usr/lib/systemd/system/hybrid-sleep.target \
            usr/lib/systemd/system/kmod-static-nodes.service \
            usr/lib/systemd/system/kmod.service \
            usr/lib/systemd/system/ldconfig.service \
            usr/lib/systemd/system/pam_namespace.service \
            usr/lib/systemd/system/procps.service \
            usr/lib/systemd/system/printer.target \
            usr/lib/systemd/system/quotaon-root.service \
            usr/lib/systemd/system/quotaon@.service \
            usr/lib/systemd/system/rc-local.service \
            usr/lib/systemd/system/rc-local.service.d \
            usr/lib/systemd/system/rpcbind.target \
            usr/lib/systemd/system-generators/systemd-bless-boot-generator \
            usr/lib/systemd/system-generators/systemd-cryptsetup-generator \
            usr/lib/systemd/system-generators/systemd-debug-generator \
            usr/lib/systemd/system-generators/systemd-factory-reset-generator \
            usr/lib/systemd/system-generators/systemd-fstab-generator \
            usr/lib/systemd/system-generators/systemd-getty-generator \
            usr/lib/systemd/system-generators/systemd-gpt-auto-generator \
            usr/lib/systemd/system-generators/systemd-hibernate-resume-generator \
            usr/lib/systemd/system-generators/systemd-integritysetup-generator \
            usr/lib/systemd/system-generators/systemd-rc-local-generator \
            usr/lib/systemd/system-generators/systemd-run-generator \
            usr/lib/systemd/system-generators/systemd-ssh-generator \
            usr/lib/systemd/system-generators/systemd-system-update-generator \
            usr/lib/systemd/system-generators/systemd-sysv-generator \
            usr/lib/systemd/system-generators/systemd-tpm2-generator \
            usr/lib/systemd/system-generators/systemd-veritysetup-generator \
            usr/lib/systemd/system/smartcard.target \
            usr/lib/systemd/system/systemd-backlight@.service \
            usr/lib/systemd/system/systemd-binfmt.service \
            usr/lib/systemd/system/systemd-bsod.service \
            usr/lib/systemd/system/systemd-ask-password-console.path \
            usr/lib/systemd/system/systemd-ask-password-console.service \
            usr/lib/systemd/system/systemd-ask-password-wall.path \
            usr/lib/systemd/system/systemd-ask-password-wall.service \
            usr/lib/systemd/system/systemd-ask-password.socket \
            usr/lib/systemd/system/systemd-ask-password@.service \
            usr/lib/systemd/system/systemd-bootctl.socket \
            usr/lib/systemd/system/systemd-bootctl@.service \
            usr/lib/systemd/system/systemd-creds.socket \
            usr/lib/systemd/system/systemd-creds@.service \
            usr/lib/systemd/system/systemd-firstboot.service \
            usr/lib/systemd/system/systemd-hibernate-clear.service \
            usr/lib/systemd/system/systemd-hibernate.service \
            usr/lib/systemd/system/systemd-hibernate.service.d \
            usr/lib/systemd/system/systemd-hybrid-sleep.service \
            usr/lib/systemd/system/systemd-hybrid-sleep.service.d \
            usr/lib/systemd/system/systemd-hostnamed.service \
            usr/lib/systemd/system/systemd-journal-catalog-update.service \
            usr/lib/systemd/system/systemd-journal-flush.service \
            usr/lib/systemd/system/systemd-journald-audit.socket \
            usr/lib/systemd/system/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/systemd-journald-varlink@.socket \
            usr/lib/systemd/system/systemd-journald-sync@.service \
            usr/lib/systemd/system/systemd-journald@.service \
            usr/lib/systemd/system/systemd-journald@.socket \
            usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-audit.socket \
            usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/systemd-localed.service \
            usr/lib/systemd/system/systemd-logind.service \
            usr/lib/systemd/system/systemd-logind-varlink.socket \
            usr/lib/systemd/system/systemd-loop@.service \
            usr/lib/systemd/system/systemd-machine-id-commit.service \
            usr/lib/systemd/system/systemd-modules-load.service \
            usr/lib/systemd/system/systemd-mute-console.socket \
            usr/lib/systemd/system/systemd-mute-console@.service \
            usr/lib/systemd/system/systemd-networkd-persistent-storage.service \
            usr/lib/systemd/system/systemd-networkd-resolve-hook.socket \
            usr/lib/systemd/system/systemd-networkd-varlink.socket \
            usr/lib/systemd/system/systemd-random-seed.service \
            usr/lib/systemd/system/systemd-resolved.service \
            usr/lib/systemd/system/systemd-resolved-monitor.socket \
            usr/lib/systemd/system/systemd-resolved-varlink.socket \
            usr/lib/systemd/system/systemd-quotacheck-root.service \
            usr/lib/systemd/system/systemd-quotacheck@.service \
            usr/lib/systemd/system/systemd-rfkill.service \
            usr/lib/systemd/system/systemd-rfkill.socket \
            usr/lib/systemd/system/systemd-storagetm.service \
            usr/lib/systemd/system/systemd-suspend.service \
            usr/lib/systemd/system/systemd-suspend.service.d \
            usr/lib/systemd/system/systemd-suspend-then-hibernate.service \
            usr/lib/systemd/system/systemd-suspend-then-hibernate.service.d \
            usr/lib/systemd/system/systemd-sysusers.service \
            usr/lib/systemd/system/systemd-tmpfiles-clean.service \
            usr/lib/systemd/system/systemd-tmpfiles-clean.timer \
            usr/lib/systemd/system/systemd-tmpfiles-setup-dev-early.service \
            usr/lib/systemd/system/systemd-tmpfiles-setup-dev.service \
            usr/lib/systemd/system/systemd-timedated.service \
            usr/lib/systemd/system/systemd-udev-load-credentials.service \
            usr/lib/systemd/system/systemd-udev-settle.service \
            usr/lib/systemd/system/systemd-udev-trigger.service \
            usr/lib/systemd/system/systemd-udevd-control.socket \
            usr/lib/systemd/system/systemd-udevd-kernel.socket \
            usr/lib/systemd/system/systemd-udevd.service \
            usr/lib/systemd/system/systemd-udevd.service.d \
            usr/lib/systemd/system/systemd-udevd-varlink.socket \
            usr/lib/systemd/system/systemd-update-done.service \
            usr/lib/systemd/system/systemd-user-sessions.service \
            usr/lib/systemd/system/systemd-validatefs@.service \
            usr/lib/systemd/systemd-networkd-wait-online \
            usr/lib/systemd/systemd-resolved \
            usr/lib/systemd/resolv.conf \
            usr/lib/systemd/resolved.conf.d \
            usr/lib/systemd/system/sleep.target \
            usr/lib/systemd/system/sound.target \
            usr/lib/systemd/system/storage-target-mode.target \
            usr/lib/systemd/system/storage-target-mode.target.wants \
            usr/lib/systemd/system/suspend.target \
            usr/lib/systemd/system/suspend-then-hibernate.target \
            usr/lib/systemd/system/sys-fs-fuse-connections.mount \
            usr/lib/systemd/system/sys-kernel-debug.mount \
            usr/lib/systemd/system/sys-kernel-tracing.mount \
            usr/lib/systemd/system/sysinit.target.wants/kmod-static-nodes.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-random-seed.service \
            usr/lib/systemd/system/syslog.socket \
            usr/lib/systemd/system/tpm2.target \
            usr/lib/systemd/system/usb-gadget.target \
            usr/lib/systemd/system/user-.slice.d \
            usr/lib/systemd/system/user-runtime-dir@.service \
            usr/lib/systemd/system/user@.service \
            usr/lib/systemd/system/user@.service.d \
            usr/lib/systemd/system/user@0.service.d \
            usr/lib/systemd/system/user.slice \
            usr/lib/systemd/systemd-backlight \
            usr/lib/systemd/systemd-binfmt \
            usr/lib/systemd/systemd-bless-boot \
            usr/lib/systemd/systemd \
            usr/lib/systemd/boot/efi/addonx64.efi.stub \
            usr/lib/systemd/boot/efi/linuxx64.efi.stub \
            usr/lib/systemd/boot/efi/systemd-bootx64.efi \
            usr/lib/systemd/systemd-cryptsetup \
            usr/lib/systemd/systemd-factory-reset \
            usr/lib/systemd/systemd-hibernate-resume \
            usr/lib/systemd/systemd-hostnamed \
            usr/lib/systemd/systemd-integritysetup \
            usr/lib/systemd/systemd-localed \
            usr/lib/systemd/systemd-logind \
            usr/lib/systemd/systemd-modules-load \
            usr/lib/systemd/systemd-mute-console \
            usr/lib/systemd/systemd-quotacheck \
            usr/lib/systemd/systemd-random-seed \
            usr/lib/systemd/systemd-rfkill \
            usr/lib/systemd/systemd-sulogin-shell \
            usr/lib/systemd/systemd-storagetm \
            usr/lib/systemd/systemd-sysv-install \
            usr/lib/systemd/systemd-timedated \
            usr/lib/systemd/systemd-tpm2-clear \
            usr/lib/systemd/systemd-tpm2-setup \
            usr/lib/systemd/systemd-udevd \
            usr/lib/systemd/systemd-user-runtime-dir \
            usr/lib/systemd/systemd-user-sessions \
            usr/lib/systemd/systemd-validatefs \
            usr/lib/systemd/systemd-veritysetup \
            usr/lib/systemd/user \
            usr/sbin/faillock \
            usr/sbin/pam_namespace_helper \
            usr/sbin/sysctl \
            usr/sbin/unix_chkpwd \
            usr/sbin/unix_update \
            usr/lib/x86_64-linux-gnu/security/pam_namespace.so \
            usr/lib/udev/ata_id \
            usr/lib/udev/cdrom_id \
            usr/lib/udev/dmi_memory_id \
            usr/lib/udev/fido_id \
            usr/lib/udev/hwdb.bin \
            usr/lib/udev/hwdb.d \
            usr/lib/udev/iocost.conf \
            usr/lib/udev/iocost \
            usr/lib/udev/mtd_probe \
            usr/lib/udev/rules.d/40-vm-hotadd.rules \
            usr/lib/udev/rules.d/50-firmware.rules \
            usr/lib/udev/rules.d/60-autosuspend.rules \
            usr/lib/udev/rules.d/60-cdrom_id.rules \
            usr/lib/udev/rules.d/60-dmi-id.rules \
            usr/lib/udev/rules.d/60-evdev.rules \
            usr/lib/udev/rules.d/60-fido-id.rules \
            usr/lib/udev/rules.d/60-input-id.rules \
            usr/lib/udev/rules.d/60-persistent-alsa.rules \
            usr/lib/udev/rules.d/60-persistent-hidraw.rules \
            usr/lib/udev/rules.d/60-persistent-input.rules \
            usr/lib/udev/rules.d/60-persistent-storage-dm.rules \
            usr/lib/udev/rules.d/60-persistent-storage-mtd.rules \
            usr/lib/udev/rules.d/60-persistent-storage-tape.rules \
            usr/lib/udev/rules.d/60-persistent-v4l.rules \
            usr/lib/udev/rules.d/60-gpiochip.rules \
            usr/lib/udev/rules.d/60-infiniband.rules \
            usr/lib/udev/rules.d/60-sensor.rules \
            usr/lib/udev/rules.d/60-serial.rules \
            usr/lib/udev/rules.d/61-persistent-storage-android.rules \
            usr/lib/udev/rules.d/64-btrfs.rules \
            usr/lib/udev/rules.d/70-camera.rules \
            usr/lib/udev/rules.d/70-joystick.rules \
            usr/lib/udev/rules.d/70-memory.rules \
            usr/lib/udev/rules.d/70-mouse.rules \
            usr/lib/udev/rules.d/70-power-switch.rules \
            usr/lib/udev/rules.d/70-touchpad.rules \
            usr/lib/udev/rules.d/70-uaccess.rules \
            usr/lib/udev/rules.d/71-power-switch-proliant.rules \
            usr/lib/udev/rules.d/71-seat.rules \
            usr/lib/udev/rules.d/73-seat-late.rules \
            usr/lib/udev/rules.d/73-special-net-names.rules \
            usr/lib/udev/rules.d/75-net-description.rules \
            usr/lib/udev/rules.d/75-probe_mtd.rules \
            usr/lib/udev/rules.d/78-graphics-card.rules \
            usr/lib/udev/rules.d/78-sound-card.rules \
            usr/lib/udev/rules.d/80-debian-compat.rules \
            usr/lib/udev/rules.d/80-drivers.rules \
            usr/lib/udev/rules.d/80-net-setup-link.rules \
            usr/lib/udev/rules.d/81-net-bridge.rules \
            usr/lib/udev/rules.d/81-net-dhcp.rules \
            usr/lib/udev/rules.d/82-net-auto-link-local.rules \
            usr/lib/udev/rules.d/90-iocost.rules \
            usr/lib/udev/rules.d/90-image-dissect.rules \
            usr/lib/udev/v4l_id \
            usr/lib/systemd/system/dpkg-db-backup.timer \
            usr/lib/systemd/system/fstrim.timer \
            usr/lib/systemd/system/systemd-hwdb-update.service \
            usr/lib/systemd/system/motd-news.timer \
            usr/lib/systemd/system/systemd-network-generator.service \
            usr/lib/systemd/system/remote-cryptsetup.target \
            usr/lib/systemd/system/remote-fs.target \
            usr/lib/systemd/system/remote-integritysetup.target \
            usr/lib/systemd/system/remote-veritysetup.target \
            usr/lib/systemd/system/dbus-org.freedesktop.hostname1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.locale1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.login1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.network1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.resolve1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.systemd1.service \
            usr/lib/systemd/system/dbus-org.freedesktop.timedate1.service \
            usr/lib/systemd/system/initrd-root-device.target.wants/remote-cryptsetup.target \
            usr/lib/systemd/system/initrd-root-device.target.wants/remote-integritysetup.target \
            usr/lib/systemd/system/initrd-root-device.target.wants/remote-veritysetup.target \
            usr/lib/systemd/system/initrd.target.wants/systemd-battery-check.service \
            usr/lib/systemd/system/initrd.target.wants/systemd-bsod.service \
            usr/lib/systemd/system/multi-user.target.wants/systemd-logind.service \
            usr/lib/systemd/system/multi-user.target.wants/systemd-user-sessions.service \
            usr/lib/systemd/system/multi-user.target.wants/getty.target \
            usr/lib/systemd/system/multi-user.target.wants/dbus.service \
            usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path \
            etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service \
            etc/systemd/system/sockets.target.wants/systemd-journald-audit.socket \
            etc/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket \
            etc/systemd/system/sockets.target.wants/systemd-networkd-resolve-hook.socket \
            etc/systemd/system/sockets.target.wants/systemd-networkd-varlink.socket \
            etc/systemd/system/sockets.target.wants/systemd-resolved-monitor.socket \
            etc/systemd/system/sockets.target.wants/systemd-resolved-varlink.socket \
            etc/systemd/system/sockets.target.wants/systemd-udevd-varlink.socket \
            etc/systemd/system/sysinit.target.wants/systemd-resolved.service \
            etc/systemd/system/systemd-journald.service.wants/systemd-journald-audit.socket \
            etc/systemd/system/systemd-journald.service.wants/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-bootctl.socket \
            usr/lib/systemd/system/sockets.target.wants/dbus.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-creds.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-hostnamed.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-ask-password.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-journald-audit.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-logind-varlink.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-mute-console.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-networkd-varlink.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-rfkill.socket \
            usr/lib/systemd/system/sockets.target.wants/systemd-udevd-varlink.socket \
            usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-audit.socket \
            usr/lib/systemd/system/systemd-journald.service.wants/systemd-journald-dev-log.socket \
            usr/lib/systemd/system/sysinit.target.wants/systemd-binfmt.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-boot-random-seed.service \
            usr/lib/systemd/system/sysinit.target.wants/ldconfig.service \
            usr/lib/systemd/system/sysinit.target.wants/proc-sys-fs-binfmt_misc.automount \
            usr/lib/systemd/system/sysinit.target.wants/sys-fs-fuse-connections.mount \
            usr/lib/systemd/system/sysinit.target.wants/sys-kernel-debug.mount \
            usr/lib/systemd/system/sysinit.target.wants/sys-kernel-tracing.mount \
            usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path \
            usr/lib/systemd/system/sysinit.target.wants/systemd-firstboot.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-hibernate-clear.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-journal-catalog-update.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-journal-flush.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-machine-id-commit.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-pcrmachine.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-pcrnvdone.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-pcrproduct.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-sysusers.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev-early.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup-dev.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-tpm2-setup-early.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-tpm2-setup.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-udev-load-credentials.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-update-done.service \
            usr/lib/systemd/system/timers.target.wants/systemd-tmpfiles-clean.timer \
            usr/lib/systemd/system/systemd-pstore.service \
            usr/lib/systemd/system/sysinit.target.wants/systemd-hwdb-update.service \
            usr/lib/systemd/systemd-network-generator \
            usr/lib/systemd/systemd-resolved \
            usr/lib/systemd/resolv.conf \
            usr/lib/systemd/resolved.conf.d \
            usr/bin/hostnamectl \
            usr/bin/networkctl \
            etc/systemd/system/sysinit.target.wants/systemd-network-generator.service \
            var/lib/systemd/deb-systemd-helper-enabled \
            usr/include \
            usr/share/doc \
            usr/share/dpkg \
            usr/share/man \
            usr/share/info \
            usr/share/locale \
            usr/share/perl \
            usr/share/perl5 \
            usr/lib/x86_64-linux-gnu/perl \
            usr/lib/x86_64-linux-gnu/perl-base \
            usr/lib/sysusers.d \
            usr/lib/sysusers.d/basic.conf \
            usr/lib/sysusers.d/debian-udev.conf \
            usr/lib/sysusers.d/dbus.conf \
            usr/lib/sysusers.d/systemd-journal.conf \
	            usr/lib/sysusers.d/systemd-network.conf \
	            usr/lib/x86_64-linux-gnu/libproc2.so.0 \
	            usr/lib/x86_64-linux-gnu/libproc2.so.0.0.2 \
	            usr/lib/modules-load.d \
            usr/lib/sysctl.d/10-coredump-debian.conf \
            usr/lib/sysctl.d/50-pid-max.conf \
            usr/lib/sysctl.d/55-bufferbloat.conf \
            usr/lib/sysctl.d/55-console-messages.conf \
            usr/lib/sysctl.d/55-ipv6-privacy.conf \
            usr/lib/sysctl.d/55-kernel-hardening.conf \
            usr/lib/sysctl.d/55-magic-sysrq.conf \
            usr/lib/sysctl.d/55-map-count.conf \
            usr/lib/sysctl.d/55-network-security.conf \
            usr/lib/sysctl.d/55-ptrace.conf \
            usr/lib/sysctl.d/55-zeropage.conf \
            usr/lib/tmpfiles.d/20-systemd-osc-context.conf \
            usr/lib/tmpfiles.d/20-systemd-shell-extra.conf \
            usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf \
            usr/lib/tmpfiles.d/20-systemd-stub.conf \
            usr/lib/tmpfiles.d/credstore.conf \
            usr/lib/tmpfiles.d/cryptsetup.conf \
            usr/lib/tmpfiles.d/debian.conf \
            usr/lib/tmpfiles.d/dbus.conf \
            usr/lib/tmpfiles.d/home.conf \
            usr/lib/tmpfiles.d/journal-nocow.conf \
            usr/lib/tmpfiles.d/legacy.conf \
            usr/lib/tmpfiles.d/libselinux1.conf \
            usr/lib/tmpfiles.d/passwd.conf \
            usr/lib/tmpfiles.d/provision.conf \
            usr/lib/tmpfiles.d/static-nodes-permissions.conf \
            usr/lib/tmpfiles.d/systemd-network.conf \
            usr/lib/tmpfiles.d/systemd-nologin.conf \
            usr/lib/tmpfiles.d/systemd-pstore.conf \
            usr/lib/tmpfiles.d/systemd-tmp.conf \
            usr/lib/tmpfiles.d/systemd.conf \
            usr/lib/tmpfiles.d/tmp.conf \
            usr/lib/tmpfiles.d/var.conf \
            usr/lib/tmpfiles.d/x11.conf \
            usr/lib/cryptsetup \
            usr/share/dbus-1 \
            usr/share/initramfs-tools \
            var/lib/systemd/random-seed \
            var/lib/dbus \
            usr/lib/cargo/bin/su \
            usr/lib/cargo/bin/sudo; do
            if [ -e "$rootfs/$path" ]; then
                fail "rootfs still contains /$path"
            else
                ok "rootfs excludes /$path"
            fi
        done

        for user in nvidia-persistenced; do
            if grep -Eq "^${user}:" "$rootfs/etc/passwd"; then
                ok "rootfs keeps static passwd entry for $user"
            else
                fail "rootfs is missing static passwd entry for $user"
            fi
        done

        for group in disk nvidia-persistenced render video; do
            if grep -Eq "^${group}:" "$rootfs/etc/group"; then
                ok "rootfs keeps static group entry for $group"
            else
                fail "rootfs is missing static group entry for $group"
            fi
        done

        rootfs_system_generator="$(
            find "$rootfs/usr/lib/systemd/system-generators" \
                -maxdepth 1 -type f -print -quit 2>/dev/null \
            || true
        )"
        if [ -n "$rootfs_system_generator" ]; then
            fail "rootfs still contains systemd generator ${rootfs_system_generator#"$rootfs"/}"
        else
            ok "rootfs excludes systemd system generators"
        fi

        rootfs_systemd_runtime_payload="$(
            {
                find "$rootfs/usr/lib/systemd" "$rootfs/etc/systemd" "$rootfs/var/lib/systemd" \
                    -mindepth 0 -print 2>/dev/null \
                || true
            } | head -n 1
        )"
	        if [ -n "$rootfs_systemd_runtime_payload" ]; then
	            fail "rootfs still contains systemd runtime/policy payload ${rootfs_systemd_runtime_payload#"$rootfs"/}"
	        else
	            ok "rootfs contains no systemd runtime/policy payload"
	        fi

	        rootfs_pam_module="$(
	            find "$rootfs/usr/lib/x86_64-linux-gnu/security" \
	                -maxdepth 1 -type f -name 'pam_*.so' -print -quit 2>/dev/null \
	            || true
	        )"
	        if [ -n "$rootfs_pam_module" ]; then
	            fail "rootfs still contains PAM module ${rootfs_pam_module#"$rootfs"/}"
	        else
	            ok "rootfs excludes PAM module policy surface"
	        fi

	        rootfs_libsystemd_payload="$(
	            find "$rootfs/usr/lib" "$rootfs/lib" \
	                \( -name 'libsystemd.so*' -o -name 'libsystemd-tinfoil*' \) \
	                -print -quit 2>/dev/null \
	            || true
	        )"
	        if [ -n "$rootfs_libsystemd_payload" ]; then
	            fail "rootfs still contains libsystemd payload ${rootfs_libsystemd_payload#"$rootfs"/}"
	        else
	            ok "rootfs excludes libsystemd shared objects and shims"
	        fi

	        rootfs_libudev_payload="$(
	            find "$rootfs/usr/lib/x86_64-linux-gnu" \
	                -maxdepth 1 \( -name 'libudev.so*' -o -name 'libudev-tinfoil*' \) \
	                -print -quit 2>/dev/null \
	            || true
	        )"
	        if [ -n "$rootfs_libudev_payload" ]; then
	            fail "rootfs still contains libudev payload ${rootfs_libudev_payload#"$rootfs"/}"
	        else
	            ok "rootfs excludes libudev shared objects and shims"
	        fi

	        rootfs_libdevmapper="$rootfs/usr/lib/x86_64-linux-gnu/libdevmapper.so.1.02.1"
	        if [ ! -s "$rootfs_libdevmapper" ]; then
	            fail "rootfs is missing no-udev libdevmapper"
	        elif ! grep -aq 'tinfoil-libdevmapper-noudev-v1' "$rootfs_libdevmapper"; then
	            fail "rootfs libdevmapper marker is missing"
	        else
	            rootfs_libdevmapper_deps="$(readelf -d "$rootfs_libdevmapper")"
	            if grep -Eq 'lib(udev|systemd|selinux)\.so' <<<"$rootfs_libdevmapper_deps"; then
	                fail "rootfs libdevmapper still links udev/systemd/selinux"
	            else
	                ok "rootfs uses Tinfoil no-udev libdevmapper"
	            fi
	        fi

	        rootfs_direct_libsystemd_dep="$(
	            find "$rootfs" -xdev -type f -print0 2>/dev/null \
	            | xargs -0 -r readelf -d 2>/dev/null \
	            | awk '
	                /^File:/ { file=$2 }
	                /NEEDED/ && /libsystemd\.so/ {
	                    print file
	                    exit
	                }
	            ' \
	            | sed "s#$rootfs/##" \
	            || true
	        )"
	        if [ -n "$rootfs_direct_libsystemd_dep" ]; then
	            fail "rootfs still has direct libsystemd dependency $rootfs_direct_libsystemd_dep"
	        else
	            ok "rootfs has no direct libsystemd dependencies"
	        fi

	        rootfs_direct_libudev_dep="$(
	            find "$rootfs" -xdev -type f -print0 2>/dev/null \
	            | xargs -0 -r readelf -d 2>/dev/null \
	            | awk '/^File:/ { file=$2 } /NEEDED/ && /libudev\.so/ { print file; exit }' \
	            | sed "s#$rootfs/##" \
	            || true
	        )"
	        if [ -n "$rootfs_direct_libudev_dep" ]; then
	            fail "rootfs still has direct libudev dependency $rootfs_direct_libudev_dep"
	        else
	            ok "rootfs has no direct libudev dependencies"
	        fi
	
	        rootfs_stale_vendor_unit_link="$(
            while IFS= read -r link; do
                target="$(readlink "$link" 2>/dev/null || true)"
                [ "$target" = "/dev/null" ] && continue
                case "$target" in
                    /*) resolved="$rootfs$target" ;;
                    *) resolved="$(dirname "$link")/$target" ;;
                esac
                if [ ! -e "$resolved" ]; then
                    printf '%s -> %s\n' "${link#"$rootfs"/}" "$target"
                    break
                fi
            done < <(find "$rootfs/usr/lib/systemd/system" -type l -print 2>/dev/null | sort)
        )"
        if [ -n "$rootfs_stale_vendor_unit_link" ]; then
            fail "rootfs contains stale vendor systemd unit symlink $rootfs_stale_vendor_unit_link"
        else
            ok "rootfs has no stale vendor systemd unit symlinks"
        fi

        rootfs_systemd_policy_payload="$(
            find "$rootfs" \
                \( -path '*/pcrlock*' \
                -o -path '*/pcrextend*' \
                -o -path '*/pcrphase*' \
                -o -path '*/tpm2-clear*' \
                -o -path '*/systemd-confext*' \
                -o -path '*/systemd-sysext*' \
                -o -path '*/systemd-factory-reset*' \
                -o -path '*/factory-reset*' \) \
                -print -quit 2>/dev/null \
            || true
        )"
        if [ -n "$rootfs_systemd_policy_payload" ]; then
            fail "rootfs still contains stock systemd policy payload ${rootfs_systemd_policy_payload#"$rootfs"/}"
        else
            ok "rootfs excludes pcrlock/factory-reset/sysext policy payload"
        fi

        rootfs_interactive_recovery_payload="$(
            find "$rootfs" \
                \( -path '*/breakpoint-pre-*' \
                -o -path '*/debug-shell.service' \
                -o -path '*/console-getty.service' \
                -o -path '*/container-getty@.service' \
                -o -path '*/getty*.service' \
                -o -path '*/getty*.target' \
                -o -path '*/serial-getty@.service' \
                -o -path '*/emergency.service' \
                -o -path '*/emergency.target' \
                -o -path '*/rescue.service' \
                -o -path '*/rescue.target' \
                -o -path '*/systemd-ask-password*' \
                -o -path '*/systemd-bsod*' \
                -o -path '*/systemd-mute-console*' \
                -o -path '*/proc-sys-fs-binfmt_misc*' \
                -o -path '*/binfmt.d' \) \
                -print -quit 2>/dev/null \
            || true
        )"
        if [ -n "$rootfs_interactive_recovery_payload" ]; then
            fail "rootfs still contains interactive recovery/debug payload ${rootfs_interactive_recovery_payload#"$rootfs"/}"
        else
            ok "rootfs excludes interactive recovery/debug shell payload"
        fi

        rootfs_stock_helper_payload="$(
            find "$rootfs" \
                \( -path '*/systemd-bootctl*' \
                -o -path '*/systemd-creds*' \
                -o -path '*/systemd-hibernate*' \
                -o -path '*/systemd-hybrid-sleep*' \
                -o -path '*/systemd-suspend*' \
                -o -path '*/systemd-rfkill*' \
                -o -path '*/systemd-quotacheck*' \
                -o -path '*/systemd-loop@.service' \
                -o -path '*/systemd-storagetm*' \
                -o -path '*/systemd-journal-catalog-update.service' \
                -o -path '*/systemd-journal-flush.service' \
                -o -path '*/systemd-machine-id-commit.service' \
                -o -path '*/systemd-random-seed*' \
                -o -path '*/systemd-update-done*' \
                -o -path '*/systemd-logind-varlink.socket' \
                -o -path '*/quotaon*' \
                -o -path '*/sleep.target' \
                -o -path '*/hibernate.target' \
                -o -path '*/hybrid-sleep.target' \
                -o -path '*/suspend.target' \
                -o -path '*/suspend-then-hibernate.target' \
                -o -path '*/storage-target-mode.target' \
                -o -path '*/sys-fs-fuse-connections.mount' \
                -o -path '*/sys-kernel-debug.mount' \
                -o -path '*/sys-kernel-tracing.mount' \
                -o -path '*/ldconfig.service' \) \
                -print -quit 2>/dev/null \
            || true
        )"
        if [ -n "$rootfs_stock_helper_payload" ]; then
            fail "rootfs still contains stock maintenance/helper payload ${rootfs_stock_helper_payload#"$rootfs"/}"
        else
            ok "rootfs excludes stock maintenance/helper payload"
        fi

        rootfs_random_seed_unit_ref="$(
            find \
                "$rootfs/usr/lib/systemd/system" \
                "$rootfs/etc/systemd/system" \
                -type f -print0 2>/dev/null \
            | xargs -0 -r grep -IlE 'systemd-random-seed|random-seed|first-boot-complete' \
            | head -n 1 \
            || true
        )"
        if [ -n "$rootfs_random_seed_unit_ref" ]; then
            fail "rootfs systemd unit graph still references random-seed surface ${rootfs_random_seed_unit_ref#"$rootfs"/}"
        else
            ok "rootfs systemd unit graph has no random-seed or first-boot-complete references"
        fi

        rootfs_initrd_unit_ref="$(
            find \
                "$rootfs/usr/lib/systemd/system" \
                "$rootfs/etc/systemd/system" \
                -type f -print0 2>/dev/null \
            | xargs -0 -r grep -IlE 'initrd[-.][^[:space:]]*\.(target|service|socket|mount)' \
            | head -n 1 \
            || true
        )"
        if [ -n "$rootfs_initrd_unit_ref" ]; then
            fail "rootfs systemd unit graph still references initrd-only unit ${rootfs_initrd_unit_ref#"$rootfs"/}"
        else
            ok "rootfs systemd unit graph has no initrd-only references"
        fi

        rootfs_link_policy="$(find "$rootfs/etc/systemd/network" "$rootfs/usr/lib/systemd/network" \
            -maxdepth 1 -type f -name '*.link' -print -quit 2>/dev/null || true)"
        if [ -n "$rootfs_link_policy" ]; then
            fail "rootfs still contains systemd link policy ${rootfs_link_policy#$rootfs}"
        else
            ok "rootfs excludes systemd link policy"
        fi

        required_execs=(
            usr/bin/awk
            usr/bin/chmod
            usr/bin/mkdir
            usr/bin/rm
            usr/sbin/ip
            usr/sbin/ip6tables
            usr/sbin/iptables
            usr/sbin/nft
        )
        for cmd in "${required_execs[@]}"; do
            if [ -x "$rootfs/$cmd" ]; then
                ok "rootfs keeps required boot command /$cmd"
            else
                fail "rootfs is missing required boot command /$cmd"
            fi
        done

        rootfs_kmod_loader_payload="$(
            find "$rootfs/usr/bin" "$rootfs/usr/sbin" "$rootfs/usr/lib/x86_64-linux-gnu" \
                \( -name depmod -o -name insmod -o -name kmod -o -name lsmod -o -name modinfo -o -name modprobe -o -name rmmod -o -name 'libkmod.so*' \) \
                -print -quit 2>/dev/null \
            || true
        )"
        if [ -n "$rootfs_kmod_loader_payload" ]; then
            fail "rootfs still contains module load/unload entrypoint ${rootfs_kmod_loader_payload#$rootfs/}"
        else
            ok "rootfs excludes module load/unload entrypoints"
        fi

        if awk -F: '$1 == "root" && $7 == "/bin/sh" { found=1 } END { exit found ? 0 : 1 }' "$rootfs/etc/passwd"; then
            ok "rootfs root account uses /bin/sh"
        else
            fail "rootfs root account does not use /bin/sh"
        fi
        if grep -Eq '(^|/)bash$|(^|/)rbash$' "$rootfs/etc/shells"; then
            fail "rootfs /etc/shells still advertises bash"
        else
            ok "rootfs /etc/shells advertises no bash shells"
        fi

        dangling_symlink=""
        while IFS= read -r -d '' symlink; do
            target="$(readlink "$symlink")"
            case "$target" in
                /*) resolved="$rootfs$target" ;;
                *) resolved="$(dirname "$symlink")/$target" ;;
            esac
            if [ ! -e "$resolved" ]; then
                dangling_symlink="$symlink"
                break
            fi
        done < <(find "$rootfs"/bin "$rootfs"/sbin "$rootfs"/usr/bin "$rootfs"/usr/sbin \
            -xdev -type l -print0 2>/dev/null)
        if [ -n "$dangling_symlink" ]; then
            fail "rootfs contains dangling executable symlink ${dangling_symlink#$rootfs}"
        else
            ok "rootfs has no dangling executable symlinks"
        fi

        privileged_exec="$(find "$rootfs" -xdev -type f -perm /6000 -print -quit 2>/dev/null || true)"
        if [ -n "$privileged_exec" ]; then
            fail "rootfs contains setuid/setgid executable ${privileged_exec#$rootfs}"
        else
            ok "rootfs has no setuid/setgid executable files"
        fi

        if command -v getcap >/dev/null 2>&1; then
            file_caps="$(getcap -r "$rootfs" 2>/dev/null | head -n 1 || true)"
            if [ -n "$file_caps" ]; then
                fail "rootfs contains file capabilities: ${file_caps#$rootfs}"
            else
                ok "rootfs has no file capabilities"
            fi
        fi

        if [ -d "$rootfs/usr/lib/firmware" ]; then
            unexpected_firmware="$(find "$rootfs/usr/lib/firmware" -mindepth 1 -maxdepth 1 \
                ! -name nvidia \
                ! -name amd-ucode \
                ! -name intel-ucode \
                -printf '%f ' 2>/dev/null)"
            if [ -n "$unexpected_firmware" ]; then
                fail "rootfs contains unexpected firmware directories: $unexpected_firmware"
            else
                ok "rootfs firmware is limited to NVIDIA and CPU microcode"
            fi
        fi

        if [ -d "$rootfs/usr/lib/modules" ]; then
            module_count="$(find "$rootfs/usr/lib/modules" -type f -name '*.ko*' 2>/dev/null | wc -l)"
            if [ "$module_count" -gt 60 ]; then
                fail "rootfs module allowlist is too broad: $module_count modules"
            else
                ok "rootfs module allowlist is bounded: $module_count modules"
            fi

            custom_kernel_release_file="$repo_dir/kernel/out/kernel.release"
            custom_kernel_builtins_file="$repo_dir/kernel/out/modules.builtin"
            if [ -s "$custom_kernel_release_file" ] && [ -s "$custom_kernel_builtins_file" ]; then
                while IFS= read -r -d '' module_dir; do
                    kver="$(basename "$module_dir")"
                    if [ "$(tr -d '\n' < "$custom_kernel_release_file")" != "$kver" ]; then
                        continue
                    fi
                    if cmp -s "$custom_kernel_builtins_file" "$module_dir/modules.builtin"; then
                        ok "rootfs modules.builtin matches the custom kernel built-in manifest for $kver"
                    else
                        fail "rootfs modules.builtin does not match the custom kernel built-in manifest for $kver"
                    fi
                done < <(find "$rootfs/usr/lib/modules" -mindepth 1 -maxdepth 1 -type d -print0)
            fi

            for module in \
                nvidia.ko \
                nvidia-modeset.ko \
                nvidia-peermem.ko \
                nvidia-uvm.ko \
                sev-guest.ko.zst \
                tdx-guest.ko \
                tsm_report.ko.zst \
                wmi.ko.zst \
                video.ko.zst \
                drm_ttm_helper.ko.zst \
                ttm.ko.zst \
                bridge.ko.zst \
                br_netfilter.ko.zst \
                veth.ko.zst \
                overlay.ko.zst \
                erofs.ko.zst \
                dm-crypt.ko.zst \
                dm-verity.ko.zst \
                aesni-intel.ko.zst \
                ecdsa_generic.ko.zst \
                stp.ko.zst \
                llc.ko.zst \
                nf_defrag_ipv4.ko.zst \
                nf_defrag_ipv6.ko.zst \
                nf_conntrack.ko.zst \
                nf_conntrack_netlink.ko.zst \
                nf_nat.ko.zst \
                nf_tables.ko.zst \
                nfnetlink.ko.zst \
                nft_chain_nat.ko.zst \
                nft_compat.ko.zst \
                nft_ct.ko.zst \
                x_tables.ko.zst \
                xt_MASQUERADE.ko.zst \
                xt_addrtype.ko.zst \
                xt_conntrack.ko.zst \
                xt_nat.ko.zst \
                xt_tcpudp.ko.zst \
                sch_fq_codel.ko.zst; do
                if find "$rootfs/usr/lib/modules" -type f -name "$module" -print -quit 2>/dev/null | grep -q .; then
                    ok "rootfs keeps required module $module"
                else
                    fail "rootfs is missing required module $module"
                fi
            done

            if find "$rootfs/usr/lib/modules" -type f -name 'nvidia-drm.ko' -print -quit 2>/dev/null | grep -q .; then
                fail "rootfs keeps nvidia-drm.ko even though PID1 does not load NVIDIA DRM"
            else
                ok "rootfs excludes nvidia-drm.ko from the compute-only NVIDIA path"
            fi

            for path in \
                kernel/arch/x86/kvm \
                kernel/drivers/ata \
                kernel/drivers/bluetooth \
                kernel/drivers/gpu/drm/amd \
                kernel/drivers/gpu/drm/ast \
                kernel/drivers/gpu/drm/bridge \
                kernel/drivers/gpu/drm/display \
                kernel/drivers/gpu/drm/gma500 \
                kernel/drivers/gpu/drm/gud \
                kernel/drivers/gpu/drm/hyperv \
                kernel/drivers/gpu/drm/i915 \
                kernel/drivers/gpu/drm/mgag200 \
                kernel/drivers/gpu/drm/nouveau \
                kernel/drivers/gpu/drm/nova \
                kernel/drivers/gpu/drm/panel \
                kernel/drivers/gpu/drm/qxl \
                kernel/drivers/gpu/drm/radeon \
                kernel/drivers/gpu/drm/scheduler \
                kernel/drivers/gpu/drm/sitronix \
                kernel/drivers/gpu/drm/solomon \
                kernel/drivers/gpu/drm/tiny \
                kernel/drivers/gpu/drm/udl \
                kernel/drivers/gpu/drm/vboxvideo \
                kernel/drivers/gpu/drm/vgem \
                kernel/drivers/gpu/drm/virtio \
                kernel/drivers/gpu/drm/vkms \
                kernel/drivers/gpu/drm/vmwgfx \
                kernel/drivers/gpu/drm/xe \
                kernel/drivers/gpu/drm/xen \
                kernel/drivers/hid \
                kernel/drivers/hwmon \
                kernel/drivers/iio \
                kernel/drivers/media \
                kernel/drivers/net/ethernet \
                kernel/drivers/net/wireless \
                kernel/drivers/platform/surface \
                kernel/drivers/platform/x86 \
                kernel/drivers/scsi \
                kernel/drivers/soundwire \
                kernel/drivers/staging \
                kernel/drivers/usb \
                kernel/sound; do
                if find "$rootfs/usr/lib/modules" -path "*/$path/*" -type f -name '*.ko*' -print -quit 2>/dev/null | grep -q .; then
                    fail "rootfs still contains disallowed module family $path"
                else
                    ok "rootfs excludes module family $path"
                fi
            done

            for module in \
                drm_buddy.ko.zst \
                drm_dma_helper.ko.zst \
                drm_exec.ko.zst \
                drm_gpusvm_helper.ko.zst \
                drm_gpuvm.ko.zst \
                drm_mipi_dbi.ko.zst \
                drm_panel_backlight_quirks.ko.zst \
                drm_suballoc_helper.ko.zst \
                drm_vram_helper.ko.zst; do
                if find "$rootfs/usr/lib/modules" -type f -name "$module" -print -quit 2>/dev/null | grep -q .; then
                    fail "rootfs still contains disallowed DRM helper $module"
                else
                    ok "rootfs excludes disallowed DRM helper $module"
                fi
            done

            unexpected_net_module="$(
                while IFS= read -r module; do
                    rel="${module#"$rootfs/usr/lib/modules/"}"
                    rel="${rel#*/}"
                    case "$rel" in
                        kernel/net/802/stp.ko.zst | \
                        kernel/net/bridge/br_netfilter.ko.zst | \
                        kernel/net/bridge/bridge.ko.zst | \
                        kernel/net/ipv4/netfilter/nf_defrag_ipv4.ko.zst | \
                        kernel/net/ipv6/netfilter/nf_defrag_ipv6.ko.zst | \
                        kernel/net/llc/llc.ko.zst | \
                        kernel/net/netfilter/nf_conntrack.ko.zst | \
                        kernel/net/netfilter/nf_conntrack_netlink.ko.zst | \
                        kernel/net/netfilter/nf_nat.ko.zst | \
                        kernel/net/netfilter/nf_tables.ko.zst | \
                        kernel/net/netfilter/nfnetlink.ko.zst | \
                        kernel/net/netfilter/nft_chain_nat.ko.zst | \
                        kernel/net/netfilter/nft_compat.ko.zst | \
                        kernel/net/netfilter/nft_ct.ko.zst | \
                        kernel/net/netfilter/x_tables.ko.zst | \
                        kernel/net/netfilter/xt_MASQUERADE.ko.zst | \
                        kernel/net/netfilter/xt_addrtype.ko.zst | \
                        kernel/net/netfilter/xt_conntrack.ko.zst | \
                        kernel/net/netfilter/xt_nat.ko.zst | \
                        kernel/net/netfilter/xt_tcpudp.ko.zst | \
                        kernel/net/sched/sch_fq_codel.ko.zst)
                            ;;
                        *)
                            printf '%s\n' "$rel"
                            break
                            ;;
                    esac
                done < <(find "$rootfs/usr/lib/modules" -path '*/kernel/net/*' -type f -name '*.ko*' 2>/dev/null | sort)
            )"
            if [ -n "$unexpected_net_module" ]; then
                fail "rootfs contains unexpected kernel/net module $unexpected_net_module"
            else
                ok "rootfs kernel/net modules match the Docker/nft evidence allowlist"
            fi

            unexpected_fs_module="$(
                while IFS= read -r module; do
                    rel="${module#"$rootfs/usr/lib/modules/"}"
                    rel="${rel#*/}"
                    case "$rel" in
                        kernel/fs/erofs/erofs.ko.zst | \
                        kernel/fs/overlayfs/overlay.ko.zst)
                            ;;
                        *)
                            printf '%s\n' "$rel"
                            break
                            ;;
                    esac
                done < <(find "$rootfs/usr/lib/modules" -path '*/kernel/fs/*' -type f -name '*.ko*' 2>/dev/null | sort)
            )"
            if [ -n "$unexpected_fs_module" ]; then
                fail "rootfs contains unexpected kernel/fs module $unexpected_fs_module"
            else
                ok "rootfs kernel/fs modules match the Docker/model evidence allowlist"
            fi

            unexpected_crypto_module="$(
                while IFS= read -r module; do
                    rel="${module#"$rootfs/usr/lib/modules/"}"
                    rel="${rel#*/}"
                    case "$rel" in
                        kernel/arch/x86/crypto/aesni-intel.ko.zst | \
                        kernel/crypto/ecdsa_generic.ko.zst)
                            ;;
                        *)
                            printf '%s\n' "$rel"
                            break
                            ;;
                    esac
                done < <(find "$rootfs/usr/lib/modules" \( -path '*/kernel/arch/x86/crypto/*' -o -path '*/kernel/crypto/*' -o -path '*/kernel/lib/crypto/*' \) -type f -name '*.ko*' 2>/dev/null | sort)
            )"
            if [ -n "$unexpected_crypto_module" ]; then
                fail "rootfs contains unexpected kernel crypto module $unexpected_crypto_module"
            else
                ok "rootfs crypto modules match the dm-crypt/NVIDIA evidence allowlist"
            fi
        fi

        rootfs_udev_payload="$(
            for path in \
                "$rootfs/etc/udev" \
                "$rootfs/usr/lib/udev" \
                "$rootfs/run/udev" \
                "$rootfs/usr/bin/udevadm" \
                "$rootfs/usr/lib/systemd/systemd-udevd" \
                "$rootfs/usr/lib/systemd/system/systemd-udevd.service" \
                "$rootfs/usr/lib/systemd/system/systemd-udevd-control.socket" \
                "$rootfs/usr/lib/systemd/system/systemd-udevd-kernel.socket" \
                "$rootfs/usr/lib/systemd/system/systemd-udevd-varlink.socket" \
                "$rootfs/usr/lib/systemd/system/systemd-udev-trigger.service" \
                "$rootfs/usr/lib/systemd/system/systemd-udev-settle.service" \
                "$rootfs/usr/lib/systemd/system/systemd-udev-load-credentials.service"; do
                if [ -e "$path" ]; then
                    printf '%s\n' "${path#"$rootfs"/}"
                    break
                fi
            done
        )"
        if [ -n "$rootfs_udev_payload" ]; then
            fail "rootfs still contains udev payload $rootfs_udev_payload"
        else
            ok "rootfs has no udev daemon, rules, hwdb, helpers, sockets, or runtime db"
        fi

        rootfs_udev_unit_ref="$(
            find \
                "$rootfs/usr/lib/systemd/system" \
                "$rootfs/etc/systemd/system" \
                -type f -print0 2>/dev/null \
            | xargs -0 -r grep -IlE 'systemd-udev|systemd-udevd|/run/udev|udevadm|/usr/lib/udev' \
            | head -n 1 \
            || true
        )"
        if [ -n "$rootfs_udev_unit_ref" ]; then
            fail "rootfs systemd unit graph still references udev ${rootfs_udev_unit_ref#"$rootfs"/}"
        else
            ok "rootfs systemd unit graph has no udev activation references"
        fi

        containerd_unit="$rootfs/usr/lib/systemd/system/containerd.service"
        if [ -e "$containerd_unit" ]; then
            fail "rootfs still contains containerd systemd unit ${containerd_unit#"$rootfs"/}"
        else
            ok "rootfs excludes containerd systemd unit"
        fi

        docker_unit="$rootfs/usr/lib/systemd/system/docker.service"
        if [ -e "$docker_unit" ]; then
            fail "rootfs still contains Docker systemd unit ${docker_unit#"$rootfs"/}"
        else
            ok "rootfs excludes Docker systemd unit"
        fi

        fabricmanager_unit="$rootfs/usr/lib/systemd/system/nvidia-fabricmanager.service"
        if [ -e "$fabricmanager_unit" ]; then
            fail "rootfs still contains NVIDIA Fabric Manager systemd unit ${fabricmanager_unit#"$rootfs"/}"
        else
            ok "rootfs excludes NVIDIA Fabric Manager systemd unit"
        fi

        rootfs_nvidia_tinfoil_conf="$rootfs/etc/modprobe.d/nvidia-lkca.conf"
        rootfs_nvidia_stock_conf="$rootfs/usr/lib/modprobe.d/nvidia-graphics-drivers.conf"
        if [ ! -f "$rootfs_nvidia_tinfoil_conf" ]; then
            fail "rootfs is missing Tinfoil NVIDIA parameter note"
        elif ! grep -Eq 'NVreg_TemporaryFilePath=/var/tmp .*NVreg_EnableS0ixPowerManagement=1 .*NVreg_PreserveVideoMemoryAllocations=1' "$rootfs_nvidia_tinfoil_conf"; then
            fail "rootfs Tinfoil NVIDIA parameter note is missing CVM runtime options"
        elif grep -Eq '^(install|remove)[[:space:]]' "$rootfs_nvidia_tinfoil_conf"; then
            fail "rootfs Tinfoil NVIDIA parameter note still contains a modprobe install/remove hook"
        else
            ok "rootfs documents Tinfoil-owned NVIDIA runtime options without modprobe hooks"
        fi
        if [ -f "$rootfs_nvidia_stock_conf" ] && grep -Eq 'NVreg_(TemporaryFilePath|EnableS0ixPowerManagement|PreserveVideoMemoryAllocations)=' "$rootfs_nvidia_stock_conf"; then
            fail "rootfs stock NVIDIA modprobe policy still contains duplicate NVIDIA runtime options"
        else
            ok "rootfs stock NVIDIA modprobe policy has no duplicate runtime options"
        fi

        rootfs_nvidia_container_config="$rootfs/etc/nvidia-container-runtime/config.toml"
        if [ ! -f "$rootfs_nvidia_container_config" ]; then
            fail "rootfs is missing NVIDIA container runtime config"
        elif grep -Eq '^load-kmods = true$' "$rootfs_nvidia_container_config"; then
            fail "rootfs NVIDIA container runtime can still invoke generic module loading"
        elif grep -Eq '^load-kmods = false$' "$rootfs_nvidia_container_config"; then
            ok "rootfs NVIDIA container runtime module loading is disabled"
        else
            fail "rootfs NVIDIA container runtime config has no explicit load-kmods=false"
        fi

        networkd_payload="$(
            find "$rootfs/etc/systemd" "$rootfs/usr/lib/systemd" "$rootfs/usr/bin" \
                \( -name 'systemd-networkd*' -o -name 'networkd.conf*' -o -name 'networkctl' \) \
                -print -quit 2>/dev/null \
            || true
        )"
        if [ -n "$networkd_payload" ]; then
            fail "rootfs still contains systemd-networkd payload ${networkd_payload#$rootfs/}"
        else
            ok "rootfs excludes systemd-networkd payload"
        fi

        tmpfiles_setup_unit="$rootfs/usr/lib/systemd/system/systemd-tmpfiles-setup.service"
        if [ -f "$tmpfiles_setup_unit" ]; then
            if grep -Eq '^After=.*systemd-sysusers\.service' "$tmpfiles_setup_unit"; then
                fail "rootfs systemd-tmpfiles-setup still orders after removed sysusers"
            else
                ok "rootfs systemd-tmpfiles-setup does not order after removed sysusers"
            fi
            if grep -Eq '^(ImportCredential=|RestrictSUIDSGID=no$)' "$tmpfiles_setup_unit"; then
                fail "rootfs systemd-tmpfiles-setup still accepts credentials or relaxes SUID/SGID policy"
            else
                ok "rootfs systemd-tmpfiles-setup has no credential imports or SUID/SGID relaxation"
            fi
        else
            ok "rootfs has no systemd-tmpfiles-setup sysusers ordering surface"
        fi

        rootfs_tmpfiles_policy="$(
            find "$rootfs/usr/lib/tmpfiles.d" "$rootfs/etc/tmpfiles.d" \
                -maxdepth 1 -type f -name '*.conf' -printf '%P\n' 2>/dev/null \
            | sort \
            || true
        )"
        if [ "$rootfs_tmpfiles_policy" = "tinfoil-runtime.conf" ]; then
            ok "rootfs tmpfiles policy is limited to tinfoil-runtime.conf"
        else
            fail "rootfs tmpfiles policy is not minimal: ${rootfs_tmpfiles_policy:-<none>}"
        fi

        rootfs_tinfoil_tmpfiles="$rootfs/usr/lib/tmpfiles.d/tinfoil-runtime.conf"
        if [ -f "$rootfs_tinfoil_tmpfiles" ]; then
            if grep -Fq '/run/cryptsetup' "$rootfs_tinfoil_tmpfiles"; then
                fail "rootfs tmpfiles policy must not create /run/cryptsetup"
            else
                ok "rootfs tmpfiles policy omits /run/cryptsetup"
            fi
            for key in \
                'd /run/lock 1777 root root -' \
                'L /run/shm - - - - /dev/shm' \
                'd /run/log/journal 2755 root systemd-journal -'; do
                if grep -Fxq "$key" "$rootfs_tinfoil_tmpfiles"; then
                    ok "rootfs tmpfiles policy keeps $key"
                else
                    fail "rootfs tmpfiles policy is missing $key"
                fi
            done
            broad_tmpfiles_surface="$(
                grep -E '(^|[[:space:]])(C!?|[aAhHrR]!?|D!|L[$+]|Z|z)[[:space:]]|/etc/|profile\.d|pstore|coredump|nologin|X11|ICE-unix|XIM-unix|font-unix|credstore|authorized_keys|tmpfiles\.\*' "$rootfs_tinfoil_tmpfiles" \
                || true
            )"
            if [ -n "$broad_tmpfiles_surface" ]; then
                fail "rootfs tmpfiles policy still contains broad distro behavior: $(printf '%s' "$broad_tmpfiles_surface" | head -n 1)"
            else
                ok "rootfs tmpfiles policy omits broad distro copy/ACL/X11/pstore behavior"
            fi
        else
            fail "rootfs is missing tinfoil-runtime tmpfiles policy"
        fi

        if [ -L "$rootfs/etc/mtab" ] && [ "$(readlink "$rootfs/etc/mtab")" = "../proc/self/mounts" ]; then
            ok "rootfs /etc/mtab is a build-time procfs symlink"
        else
            fail "rootfs /etc/mtab is not the expected build-time procfs symlink"
        fi

        if [ -e "$rootfs/usr/lib/systemd/system/systemd-sysctl.service" ]; then
            fail "rootfs still contains systemd-sysctl.service"
        else
            ok "rootfs excludes systemd-sysctl.service"
        fi

        rootfs_sysctl_policy="$(
            find "$rootfs/usr/lib/sysctl.d" "$rootfs/etc/sysctl.d" \
                -maxdepth 1 -type f -name '*.conf' -printf '%P\n' 2>/dev/null \
            | sort \
            || true
        )"
        if [ "$rootfs_sysctl_policy" = "tinfoil-runtime.conf" ]; then
            ok "rootfs sysctl policy is limited to tinfoil-runtime.conf"
        else
            fail "rootfs sysctl policy is not minimal: ${rootfs_sysctl_policy:-<none>}"
        fi

        rootfs_tinfoil_sysctl="$rootfs/usr/lib/sysctl.d/tinfoil-runtime.conf"
        if [ -f "$rootfs_tinfoil_sysctl" ]; then
            for key in \
                'kernel.kptr_restrict = 1' \
                'kernel.printk = 4 4 1 7' \
                'kernel.sysrq = 0' \
                'kernel.yama.ptrace_scope = 1' \
                '-net.core.default_qdisc = fq_codel' \
                'net.ipv4.conf.default.rp_filter = 2' \
                'net.ipv4.conf.all.rp_filter = 2' \
                'vm.max_map_count = 1048576' \
                'vm.mmap_min_addr = 65536'; do
                if grep -Fxq -- "$key" "$rootfs_tinfoil_sysctl"; then
                    ok "rootfs sysctl policy keeps $key"
                else
                    fail "rootfs sysctl policy is missing $key"
                fi
            done
            broad_sysctl_surface="$(
                grep -Ev '^[[:space:]]*(#|$)' "$rootfs_tinfoil_sysctl" \
                | grep -Ev '^(kernel\.kptr_restrict = 1|kernel\.printk = 4 4 1 7|kernel\.sysrq = 0|kernel\.yama\.ptrace_scope = 1|-net\.core\.default_qdisc = fq_codel|net\.ipv4\.conf\.default\.rp_filter = 2|net\.ipv4\.conf\.all\.rp_filter = 2|vm\.max_map_count = 1048576|vm\.mmap_min_addr = 65536)$' \
                || true
            )"
            if [ -n "$broad_sysctl_surface" ]; then
                fail "rootfs sysctl policy contains unexpected setting: $(printf '%s' "$broad_sysctl_surface" | head -n 1)"
            else
                ok "rootfs sysctl policy contains only the Tinfoil allowlist"
            fi
        else
            fail "rootfs is missing tinfoil-runtime sysctl policy"
        fi

        rootfs_modules_load_surface="$(
            for path in \
                "$rootfs/etc/modules-load.d" \
                "$rootfs/usr/lib/modules-load.d" \
                "$rootfs/usr/lib/systemd/system/systemd-modules-load.service" \
                "$rootfs/etc/systemd/system/sysinit.target.wants/systemd-modules-load.service" \
                "$rootfs/usr/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service" \
                "$rootfs/usr/lib/systemd/systemd-modules-load"; do
                if [ -e "$path" ]; then
                    printf '%s\n' "${path#"$rootfs"/}"
                    break
                fi
            done
        )"
        if [ -n "$rootfs_modules_load_surface" ]; then
            fail "rootfs still contains modules-load surface $rootfs_modules_load_surface"
        else
            ok "rootfs has no systemd-modules-load service, helper, wants links, or policy directories"
        fi

        if [ -e "$rootfs/usr/lib/systemd/system/systemd-journald.service" ]; then
            fail "rootfs still contains systemd-journald.service"
        else
            ok "rootfs excludes systemd-journald.service"
        fi

        if [ -L "$rootfs/etc/resolv.conf" ]; then
            fail "rootfs /etc/resolv.conf is still a symlink"
        elif grep -Eq '^nameserver 1\.1\.1\.1$' "$rootfs/etc/resolv.conf" && grep -Eq '^nameserver 1\.0\.0\.1$' "$rootfs/etc/resolv.conf"; then
            ok "rootfs has static resolver config"
        else
            fail "rootfs /etc/resolv.conf does not contain the expected static resolvers"
        fi

        if grep -Eq '^hosts:[[:space:]]+files[[:space:]]+dns$' "$rootfs/etc/nsswitch.conf"; then
            ok "rootfs nsswitch uses files/dns host lookup"
        else
            fail "rootfs nsswitch still uses resolved or an unexpected host lookup path"
        fi

        for glob in "$rootfs"/usr/src/linux-headers-*; do
            if [ -e "$glob" ]; then
                fail "rootfs still contains ${glob#$rootfs}"
            fi
        done

        banned_bin_patterns=(
            cc
            'gcc*'
            'g++*'
            'cpp*'
            make
            patch
            dkms
            addr2line
            ar
            as
            ld
            ldd
            nm
            objcopy
            objdump
            pahole
            pkg-config
            pkgconf
            ranlib
            readelf
            size
            strings
            strip
            'gnu*'
            '*gcc*'
            'deb-systemd-*'
            'debconf*'
            'dpkg*'
            'perl*'
            'cpan*'
            pod2*
            ptar*
            xsubpp
            bash
            bashbug
            rbash
            btfdiff
            codiff
            corelist
            ctracer
            dtagnames
            enc2xs
            encguess
            fullcircle
            'gprofng*'
            h2ph
            h2xs
            instmodsh
            json_pp
            kernel-install
            'linux-*'
            localedef
            lsb_release
            nvidia-bug-report.sh
            pdwtags
            pfunct
            pglobal
            piconv
            pl2pm
            prefcnt
            prove
            rpcgen
            scncopy
            shasum
            splain
            systemd-firstboot
            systemd-hwdb
            zipdetails
            bootctl
            busctl
            chage
	            chfn
	            chsh
	            chrt
	            choom
	            'dbus-cleanup-sockets'
	            'dbus-monitor'
	            'dbus-run-session'
	            'dbus-send'
	            'dbus-update-activation-environment'
	            'dbus-uuidgen'
	            dmesg
	            'efiboot*'
	            expiry
	            fallocate
	            fincore
	            findmnt
	            flock
	            free
	            gencat
	            gpasswd
	            hardlink
	            hostnamectl
	            ionice
	            ipcmk
	            ipcrm
	            ipcs
	            logger
	            locale
	            localectl
	            loginctl
	            lsblk
	            lsipc
	            lsirq
	            lslocks
	            lslogins
	            lsmem
	            mcookie
	            mesg
	            mount
	            mountpoint
	            namei
	            nsenter
	            networkctl
	            nvidia-debugdump
	            nvidia-ngx-updater
	            nvidia-powerd
	            nvidia-sleep.sh
	            passwd
	            prlimit
	            rename.ul
	            rev
	            script
	            scriptlive
	            scriptreplay
	            setarch
	            setpriv
	            setsid
	            su
	            taskset
	            systemd-analyze
            systemd-cgls
            systemd-cgtop
            systemd-delta
            systemd-inhibit
            systemd-mount
            systemd-random-seed
            systemd-run
            systemd-sysusers
	            systemd-sysext
	            sysctl
	            timedatectl
	            ul
	            umount
	            unshare
	            utmpdump
	            wall
	            whereis
	            add-shell
            adduser
	            agetty
	            blkid
	            blockdev
	            cfdisk
	            chgpasswd
	            chpasswd
	            cryptsetup
	            deluser
	            dmsetup
	            dmstats
	            veritysetup
	            fdisk
	            fsck
	            groupadd
            groupdel
            groupmod
            grpck
            grpconv
            grpunconv
	            iucode_tool
	            losetup
	            mkfs
	            mkswap
	            newusers
	            pam-auth-update
	            'pam_*'
	            pivot_root
            pwck
            pwconv
            pwhistory_helper
            pwunconv
            remove-shell
            runuser
	            shadowconfig
	            sfdisk
	            sulogin
	            swapoff
	            swapon
            update-passwd
            update-shells
            update-alternatives
            useradd
            userdel
	            usermod
	            vipw
	            wipefs
            strace
            tcpdump
            curl
            wcurl
            ping
            ping4
            ping6
            dmidecode
            lshw
            lspci
            lsusb
            cron
            crond
            man
            nano
        )
        for bin in "${banned_bin_patterns[@]}"; do
            if find "$rootfs"/bin "$rootfs"/sbin "$rootfs"/usr/bin "$rootfs"/usr/sbin \
                -xdev \( \( -type f -perm -111 \) -o -type l \) -name "$bin" -print -quit 2>/dev/null | grep -q .; then
                fail "rootfs contains banned executable matching $bin"
            else
                ok "rootfs excludes executable matching $bin"
            fi
        done

        banned_helper_paths=(
            etc/bash.bashrc
            etc/security/namespace.init
            etc/skel/.bash_logout
            etc/skel/.bashrc
            root/.bash_logout
            root/.bashrc
            usr/share/base-files/dot.bashrc
            usr/share/debianutils/shells.d/bash
            usr/share/dot.bashrc
            usr/bin/bzdiff
            usr/bin/bzexe
            usr/bin/bzgrep
            usr/bin/bzmore
            usr/bin/c_rehash
            usr/bin/egrep
            usr/bin/fgrep
            usr/bin/gunzip
            usr/bin/gzexe
            usr/bin/lzcmp
            usr/bin/lzdiff
            usr/bin/lzegrep
            usr/bin/lzfgrep
            usr/bin/lzgrep
            usr/bin/lzless
            usr/bin/lzmore
            usr/bin/make-first-existing-target
            usr/bin/rgrep
            usr/bin/routel
            usr/bin/savelog
            usr/bin/streamzip
            usr/bin/tzselect
            usr/bin/which
            usr/bin/which.debianutils
            usr/bin/xzdiff
            usr/bin/xzgrep
            usr/bin/xzless
            usr/bin/xzmore
            usr/bin/zcat
            usr/bin/zcmp
            usr/bin/zdiff
            usr/bin/zegrep
            usr/bin/zfgrep
            usr/bin/zforce
            usr/bin/zgrep
            usr/bin/zless
            usr/bin/zmore
            usr/bin/znew
            usr/local/bin/check-nvidia-fabric
            usr/local/bin/check-nvidia-gpu
            usr/libexec/libselinux/selinux_compile_fcontexts
            usr/sbin/blkdeactivate
            usr/sbin/cryptdisks_start
            usr/sbin/cryptdisks_stop
            usr/sbin/iptables-apply
            usr/sbin/luksformat
            usr/sbin/tarcat
            usr/sbin/update-ca-certificates
        )
        for helper in "${banned_helper_paths[@]}"; do
            if [ -e "$rootfs/$helper" ]; then
                fail "rootfs contains stale helper script /$helper"
            else
                ok "rootfs excludes stale helper script /$helper"
            fi
        done
    fi
fi

if [ "$failures" -ne 0 ]; then
    echo "tcb-check: $failures failure(s)" >&2
    exit 1
fi

echo "tcb-check: all checks passed"
