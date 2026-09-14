{
  pkgs,
  initrd,
  repartSeed,
}:
let
  go = import ../nix/go.nix {
    inherit pkgs;
    commands = {
      boot = "cmd/sandbox-boot";
      pid1 = "cmd/sandbox-pid1";
      shim = "cmd/sandbox-shim";
      sandbox = "cmd/sandbox";
      volume-worker = "cmd/volumeworker";
    };
    pid1Package = "cmd/sandbox-pid1";
  };
  ubuntu = import ../nix/runtime-packages.nix {
    inherit pkgs;
    name = "cvmimage-sandbox-packages-lock";
    lockFile = ./packages-lock.nix;
    securitySnapshot = {
      timestamp = "20260721";
      sha256 = "f943c10bd75f3cc0ef581027e6008f287d7634df7fcd5700105b76a11acea88e";
    };
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
      "e2fsprogs"
      "openssh-server"
    ];
  };
  kernel = import ../nix/kernel.nix {
    inherit pkgs;
    extraConfigs = [ ./kernel.config ];
  };
  debugKernel = import ../nix/kernel.nix {
    inherit pkgs;
    extraConfigs = [ ./kernel.config ];
    debugConsole = true;
  };
  rootfs = import ../nix/rootfs.nix {
    inherit pkgs;
    ubuntuDebs = ubuntu.packages;
    runtimeGo = go.packages.runtime-go;
    debugPID1 = go.packages.debug-pid1;
    enableGPU = false;
    enableContainers = false;
    commands = [
      "boot"
      "pid1"
      "shim"
      "sandbox"
      "volume-worker"
    ];
    accountRoot = ./rootfs/etc;
    extraPayloadPaths = [
      "usr/bin/ssh-keygen"
      "usr/lib/openssh/sshd-auth"
      "usr/lib/openssh/sshd-session"
      "usr/sbin/sshd"
    ];
    files = [
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
    extraInstall = ''
      mkdir -p "$root/nix" "$root/workspace"
      link_new usr/bin "$root/bin"
      for command in bash env sh; do
        link_new "/nix/var/nix/profiles/default/bin/$command" "$root/usr/bin/$command"
      done
    '';
  };
  image =
    kernelArtifacts: extra:
    import ../nix/image.nix (
      {
        inherit pkgs initrd repartSeed;
        rootfs = rootfs.rootfs;
        kernel = "${kernelArtifacts}/tinfoil-custom.vmlinuz";
        repartDefinitions = ../repart.d;
      }
      // extra
    );
in
{
  runtime-go = go.packages.runtime-go;
  debug-pid1 = go.packages.debug-pid1;
  rootfs-archive = rootfs.rootfs;
  package-lock = ubuntu.lock;
  kernel-artifacts = kernel.artifacts;
  debug-kernel-artifacts = debugKernel.artifacts;
  shipping-image = image kernel.artifacts { basename = "tinfoilcvm-sandbox"; };
  debug-image = image debugKernel.artifacts {
    basename = "tinfoilcvm-sandbox-debug";
    debugLayer = rootfs.debugLayer;
  };
}
