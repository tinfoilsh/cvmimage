{ pkgs, go }:
let
  payload = import ./payload.nix { inherit pkgs; };
  packageNames = [
    "ca-certificates"
    "iproute2"
    "nftables"
    "libc6"
    "libc-bin"
    "libcap2"
    "libxml2-16"
    "libstdc++6"
    "libgcc-s1"
    "zlib1g"
    "libtirpc3t64"
    "libtirpc-common"
    "libseccomp2"
    "libblkid1"
    "libuuid1"
  ];
  ubuntu = import ./runtime-packages.nix {
    inherit pkgs packageNames;
    name = "cvmimage-runtime-packages-lock";
    lockFile = ./runtime-packages-lock.nix;
  };
  ubuntuTree = payload.debTree "cvmimage-platform-ubuntu" ubuntu.packages;
  module = {
    src = go.source [ ../tinfoil ];
    modRoot = "tinfoil";
    vendorHash = "sha256-fN82EZ+6eI6c+ThhB0uCVxMGxm93sR7m9SADkj6B+Z4=";
  };
  tinfoilInitrd = go.initrd module;
  initrd = import ./initrd.nix { inherit pkgs tinfoilInitrd; };
  checks = go.checks {
    name = "tinfoil-platform-checks";
    module = module // {
      src = pkgs.lib.fileset.toSource {
        root = ../.;
        fileset = pkgs.lib.fileset.unions [
          (go.fileset ../tinfoil)
          ../image
          ../repart.d
        ];
      };
    };
    extraChecks = ''
      go test -race ./pid1 ./internal/boot/...
      go test -tags=tinfoil_debug_image ./pid1
    '';
  };
  manifest = {
    payloads = [
      {
        archive = ubuntuTree.archive;
        paths = [
          "etc/bindresvport.blacklist"
          "etc/gai.conf"
          "etc/ld.so.conf"
          "etc/ld.so.conf.d"
          "etc/netconfig"
          "etc/ssl/openssl.cnf"
          "usr/bin/ip"
          "usr/lib/ssl/cert.pem"
          "usr/lib/ssl/certs"
          "usr/lib/ssl/openssl.cnf"
          "usr/lib/ssl/private"
          "usr/lib/x86_64-linux-gnu"
          "usr/lib64/ld-linux-x86-64.so.2"
          "usr/sbin/ip"
          "usr/sbin/ldconfig"
          "usr/sbin/nft"
        ];
      }
    ];
    files = [
      {
        source = ../image/rootfs/etc/.pwd.lock;
        target = "etc/.pwd.lock";
        mode = "0600";
      }
      {
        source = ../image/rootfs/etc/hostname;
        target = "etc/hostname";
        mode = "0644";
      }
      {
        source = ../image/rootfs/etc/hosts;
        target = "etc/hosts";
        mode = "0644";
      }
      {
        source = ../image/rootfs/etc/nsswitch.conf;
        target = "etc/nsswitch.conf";
        mode = "0644";
      }
      {
        source = ../image/rootfs/etc/resolv.conf;
        target = "etc/resolv.conf";
        mode = "0644";
      }
      {
        source = ../image/rootfs/usr/lib/clock-epoch;
        target = "usr/lib/clock-epoch";
        mode = "0644";
      }
      {
        source = ../image/rootfs/usr/lib/os-release;
        target = "usr/lib/os-release";
        mode = "0644";
      }
      {
        source = payload.caBundle ubuntuTree;
        target = "etc/ssl/certs/ca-certificates.crt";
        mode = "0644";
      }
      {
        source = ../image/rootfs/etc/nftables.conf;
        target = "etc/nftables.conf";
        mode = "0644";
      }
    ];
    directories =
      map
        (path: {
          inherit path;
          mode = "0755";
        })
        [
          "dev"
          "mnt"
          "mnt/ramdisk"
          "proc"
          "run"
          "sys"
          "tmp"
          "var"
          "var/tmp"
          "usr/bin"
          "usr/lib64"
          "etc/ssl/certs"
          "var/cache/ldconfig"
        ]
      ++ [
        {
          path = "etc/ssl/private";
          mode = "0700";
        }
      ];
    symlinks = [
      {
        source = "usr/lib64";
        target = "lib64";
      }
      {
        source = "usr/sbin";
        target = "sbin";
      }
      {
        source = "../run";
        target = "var/run";
      }
    ];
  };
in
{
  inherit
    packageNames
    ubuntu
    manifest
    initrd
    tinfoilInitrd
    checks
    ;
}
