{
  pkgs,
  go,
  platform,
}:
let
  payload = import ../nix/payload.nix { inherit pkgs; };
  module = {
    src = go.source [
      ../tinfoil
      ./.
    ];
    modRoot = "sandbox";
    proxyVendor = true;
    vendorHash = "sha256-1poiO6LBNJsPAjXAEXVaOq2hPT08G1yiNMBOTnziJUY=";
  };
  ubuntu = import ../nix/runtime-packages.nix {
    inherit pkgs;
    name = "cvmimage-sandbox-packages-lock";
    packageNames = platform.packageNames ++ [
      "e2fsprogs"
      "openssh-server"
    ];
    lockFile = ./packages-lock.nix;
  };
in
{
  basename = "tinfoilcvm-sandbox";
  inherit module;
  commands = [
    "boot"
    "pid1"
    "shim"
    "sandbox"
  ];
  kernelConfigs = [ ./kernel.config ];
  checks = go.checks {
    name = "tinfoil-sandbox-checks";
    module = module // {
      src = pkgs.lib.fileset.toSource {
        root = ../.;
        fileset = pkgs.lib.fileset.unions [
          (go.fileset ../tinfoil)
          (go.fileset ./.)
          ./rootfs/etc/nftables.conf
        ];
      };
    };
    extraChecks = "go test -tags=tinfoil_debug_image ./cmd/pid1";
  };
  rootfs = { kernel }: {
    outputs."sandbox-package-lock" = ubuntu.lock;
    manifest = {
      payloads = [
        {
          archive =
            (payload.debTree "cvmimage-ext4" (
              ubuntu.select [
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
        {
          archive =
            (payload.debTree "cvmimage-openssh" (
              ubuntu.select [
                "openssh-server"
                "openssh-client"
                "libaudit1"
                "libcap-ng0"
                "libcrypt1"
                "libpam0g"
                "libwrap0"
              ]
            )).archive;
          paths = [
            "usr/bin/ssh-keygen"
            "usr/lib/openssh/sshd-auth"
            "usr/lib/openssh/sshd-session"
            "usr/lib/x86_64-linux-gnu/libaudit.so.1"
            "usr/lib/x86_64-linux-gnu/libaudit.so.1.0.0"
            "usr/lib/x86_64-linux-gnu/libcap-ng.so.0"
            "usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0"
            "usr/lib/x86_64-linux-gnu/libcrypt.so.1"
            "usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0"
            "usr/lib/x86_64-linux-gnu/libpam.so.0"
            "usr/lib/x86_64-linux-gnu/libpam.so.0.85.1"
            "usr/lib/x86_64-linux-gnu/libwrap.so.0"
            "usr/lib/x86_64-linux-gnu/libwrap.so.0.7.6"
            "usr/sbin/sshd"
          ];
        }
      ];
      files = payload.accounts ./rootfs/etc ++ [
        {
          source = ./rootfs/etc/nftables.conf;
          target = "etc/nftables.conf";
          mode = "0644";
        }

        {
          source = ./rootfs/etc/nix/nix.conf;
          target = "etc/nix/nix.conf";
          mode = "0644";
        }
        {
          source = ./rootfs/etc/profile;
          target = "etc/profile";
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
            "nix"
            "workspace"
          ];
      symlinks = [
        {
          source = "usr/bin";
          target = "bin";
        }
      ]
      ++
        map
          (command: {
            source = "/nix/var/nix/profiles/default/bin/${command}";
            target = "usr/bin/${command}";
          })
          [
            "bash"
            "env"
            "sh"
          ];
    };
  };
}
