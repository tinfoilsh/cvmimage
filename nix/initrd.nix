{
  pkgs,
  tinfoilInitrd,
}:

pkgs.runCommand "initrd.cpio.zst" { allowedReferences = [ ]; } ''
  set -Eeuo pipefail
  umask 0022

  ${pkgs.coreutils}/bin/install -d -m0755 \
    root/dev root/proc root/run root/sys root/usr root/usr/bin
  ${pkgs.coreutils}/bin/ln -s usr/bin/tinfoil-initrd root/init
  ${pkgs.coreutils}/bin/install -m0755 \
    ${tinfoilInitrd}/bin/tinfoil-initrd root/usr/bin/tinfoil-initrd
  ${pkgs.coreutils}/bin/touch -h -d @0 \
    root/dev root/init root/proc root/run root/sys root/usr \
    root/usr/bin root/usr/bin/tinfoil-initrd

  printf '%s\0' \
    dev init proc run sys usr usr/bin usr/bin/tinfoil-initrd \
    | (cd root && ${pkgs.cpio}/bin/cpio \
        --quiet --create --format=newc --owner=+0:+0 \
        --reproducible --null) \
    | ${pkgs.zstd}/bin/zstd -q -T1 -19 --no-progress -c > "$out"
''
