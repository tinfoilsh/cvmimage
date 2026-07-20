#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

lvm2_version="2.03.31-2ubuntu3"
libdm_abi="1.02.1"
cache_dir="$repo_dir/mkosi.cache/libdevmapper-noudev"
apt_dir="$cache_dir/apt"
src_parent="$cache_dir/src"
src_dir="$src_parent/lvm2-2.03.31"
build_dir="$cache_dir/build"

apt_opts=(
    -o "Dir::Etc::sourcelist=$apt_dir/etc/sources.list"
    -o "Dir::Etc::sourceparts=-"
    -o "Dir::Etc::main=/dev/null"
    -o "Dir::State::lists=$apt_dir/lists"
    -o "Dir::Cache=$apt_dir/cache"
)

mkdir -p "$apt_dir/etc" "$apt_dir/lists/partial" "$apt_dir/cache/archives/partial" "$src_parent"
cat > "$apt_dir/etc/sources.list" <<'EOF'
deb-src http://archive.ubuntu.com/ubuntu resolute main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu resolute-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu resolute-backports main restricted universe multiverse
deb-src http://security.ubuntu.com/ubuntu resolute-security main restricted universe multiverse
EOF

apt-get "${apt_opts[@]}" update
rm -rf "$src_dir" "$build_dir"
(
    cd "$src_parent"
    apt-get "${apt_opts[@]}" source "lvm2=$lvm2_version"
)

patch --directory="$src_dir" --strip=1 <<'PATCH'
--- a/libdm/libdm-common.c
+++ b/libdm/libdm-common.c
@@ -2277,6 +2277,8 @@ int dm_task_set_cookie(struct dm_task *dmt, uint32_t *cookie, uint16_t flags)
 	return 1;
 }
 
+const char tinfoil_libdevmapper_noudev_marker[] = "tinfoil-libdevmapper-noudev-v1";
+
 int dm_udev_complete(uint32_t cookie)
 {
 	return 1;
PATCH

patch --directory="$src_dir" --strip=1 <<'PATCH'
--- a/libdm/libdm-common.c
+++ b/libdm/libdm-common.c
@@ -2279,6 +2279,12 @@ int dm_task_set_cookie(struct dm_task *dmt, uint32_t *cookie, uint16_t flags)
 
 const char tinfoil_libdevmapper_noudev_marker[] = "tinfoil-libdevmapper-noudev-v1";
 
+int dm_udev_create_cookie(uint32_t *cookie)
+{
+	*cookie = 0;
+	return 1;
+}
+
 int dm_udev_complete(uint32_t cookie)
 {
 	return 1;
PATCH

mkdir -p "$build_dir"
(
    cd "$build_dir"
    "$src_dir/configure" \
        --prefix=/usr \
        --exec-prefix=/usr \
        --libdir=/usr/lib/x86_64-linux-gnu \
        --with-usrlibdir=/usr/lib/x86_64-linux-gnu \
        --with-device-uid=0 \
        --with-device-gid=6 \
        --with-device-mode=0660 \
        --with-default-pid-dir=/run \
        --with-default-run-dir=/run/lvm \
        --with-default-locking-dir=/run/lock/lvm \
        --with-cache=internal \
        --with-thin=none \
        --with-symvers=gnu \
        --without-udev \
        --without-systemd \
        --disable-udev_sync \
        --disable-udev_rules \
        --disable-selinux \
        --disable-systemd-journal \
        --disable-dmeventd \
        --disable-cmdlib \
        --disable-lvmpolld \
        --disable-lvmlockd-dlm \
        --disable-lvmlockd-sanlock \
        --disable-notify-dbus \
        --disable-readline \
        --disable-editline \
        --enable-pkgconfig \
        --enable-write_install
    make V=1 "LIB_VERSION_DM=$libdm_abi" device-mapper
)

built_lib="$build_dir/libdm/ioctl/libdevmapper.so.$libdm_abi"
if ! grep -aq 'tinfoil-libdevmapper-noudev-v1' "$built_lib"; then
    echo "built libdevmapper is missing Tinfoil no-udev marker" >&2
    exit 1
fi
dynamic_deps="$(readelf -d "$built_lib")"
if grep -Eq 'lib(udev|systemd|selinux)\.so' <<<"$dynamic_deps"; then
    echo "built libdevmapper still links udev/systemd/selinux" >&2
    printf '%s\n' "$dynamic_deps" >&2
    exit 1
fi
symbols="$(readelf -Ws "$built_lib")"
if ! grep -Fq 'dm_udev_create_cookie@@Base' <<<"$symbols"; then
    echo "built libdevmapper is missing dm_udev_create_cookie compatibility export" >&2
    exit 1
fi

strip --strip-unneeded "$built_lib"

install -D -m 0755 "$built_lib" "$repo_dir/mkosi.extra/usr/lib/x86_64-linux-gnu/libdevmapper.so.$libdm_abi"
rm -f "$repo_dir/mkosi.images/initrd/mkosi.extra/usr/lib/x86_64-linux-gnu/libdevmapper.so.$libdm_abi"

echo "built no-udev libdevmapper $libdm_abi from lvm2 $lvm2_version"
