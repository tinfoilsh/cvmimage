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
    modRoot = "cvmimage/sandbox";
    proxyVendor = true;
    vendorHash = "sha256-TRDrJY0oyQwj0t5+arXAfyr2mKpOIScFVg7GAX0DH4g=";
  };
  ubuntu = import ../nix/runtime-packages.nix {
    inherit pkgs;
    name = "cvmimage-sandbox-packages-lock";
    packageNames = platform.packageNames ++ [
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
  kernelConfigs = [ ];
  checks = go.checks {
    name = "tinfoil-sandbox-checks";
    forbiddenDependencies = [
      "tinfoil/inference"
      "github.com/NVIDIA"
      "github.com/containerd"
      "github.com/docker"
      "github.com/moby"
    ];
    module = module // {
      src = go.withSchema (
        pkgs.lib.fileset.toSource {
          root = ../.;
          fileset = pkgs.lib.fileset.unions [
            (go.fileset ../tinfoil)
            (go.fileset ./.)
            ./rootfs/etc/nftables.conf
          ];
        }
      );
    };
    extraChecks = ''
      go test -race ./cmd/sandbox
      go test -tags=tinfoil_debug_image ./cmd/pid1
    '';
  };
  rootfs = { kernel }: {
    outputs."sandbox-package-lock" = ubuntu.lock;
    manifest = {
      payloads = [
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
