#!/bin/sh
set -eu
root=$(mktemp -d /tmp/tinfoil-volume-initramfs.XXXXXX)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/bin" "$root/sbin" "$root/usr/bin" "$root/usr/sbin" "$root/lib" \
    "$root/usr/lib" "$root/proc" "$root/sys" "$root/dev" "$root/run" "$root/tmp"
chmod 1777 "$root/tmp"
cp /bin/busybox "$root/bin/"
for tool in sh mount mkdir poweroff sync uname; do
    ln -s busybox "$root/bin/$tool"
done
cp /bin/kmod "$root/bin/"
ln -s /bin/kmod "$root/sbin/modprobe"
cp /lib/*.so* "$root/lib/"
cp /usr/lib/*.so* "$root/usr/lib/"
cp -a /lib/modules "$root/lib/"
cp /sbin/mke2fs "$root/usr/sbin/mkfs.ext4"
cp /volume.test "$root/volume.test"
cp /hardening.test "$root/hardening.test"
cp /tinfoil-volume-worker "$root/usr/bin/tinfoil-volume-worker"
cp /fixture/init.sh "$root/init"
chmod 755 "$root/init"
cd "$root"
find . -print0 | cpio --null -o -H newc | gzip -1 > /fixture/initramfs.gz
