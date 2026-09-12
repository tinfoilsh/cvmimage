{ pkgs, payload }:
let
  packages = import ./runtime-packages.nix {
    inherit pkgs;
    name = "cvmimage-storage-packages-lock";
    packageNames = [ "e2fsprogs" ];
    lockFile = ./storage-packages-lock.nix;
  };
in
{
  payloads = [
    {
      archive =
        (payload.debTree "cvmimage-ext4" (
          packages.select [
            "e2fsprogs"
            "libext2fs2t64"
            "libss2"
            "logsave"
          ]
        )).archive;
      paths = [
        "etc/mke2fs.conf"
        "usr/sbin/mke2fs"
        "usr/sbin/mkfs.ext4"
        "usr/lib/x86_64-linux-gnu"
      ];
    }
  ];
}
