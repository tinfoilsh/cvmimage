{
  system ? "x86_64-linux",
}:

assert system == "x86_64-linux";

let
  nixpkgsLock = builtins.fromJSON (builtins.readFile ./nixpkgs.lock.json);
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsLock) url sha256;
  };
  pkgs = import nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
  go = import ./nix/go.nix { inherit pkgs; };
  initrd = import ./nix/initrd.nix {
    inherit pkgs;
    tinfoilInitrd = go.packages."tinfoil-initrd";
  };
  kernel = import ./nix/kernel.nix { inherit pkgs; };
  debugKernel = import ./nix/kernel.nix {
    inherit pkgs;
    debugConsole = true;
  };
  nvidia = import ./nix/nvidia-modules.nix { inherit pkgs kernel; };
  nvattest = import ./nix/nvattest.nix { inherit pkgs; };
  runtimePackages = import ./nix/runtime-packages.nix { inherit pkgs; };
  rootfs = import ./nix/rootfs.nix {
    inherit pkgs;
    ubuntuDebs = runtimePackages.packages;
    runtimeGo = go.packages."runtime-go";
    debugPID1 = go.packages."debug-pid1";
    inherit (nvattest) nvattest;
    nvidiaModules = map (name: "${nvidia.modules}/${name}") nvidia.moduleNames;
  };
  repartSeedText = builtins.readFile ./repart.d/seed;
  repartSeedMatch = builtins.match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\n" repartSeedText;
  repartSeed = assert repartSeedMatch != null; builtins.head repartSeedMatch;
  image = import ./nix/image.nix;
  buildImage = kernelArtifacts: extraArgs: image ({
    inherit pkgs repartSeed;
    rootfs = rootfs.rootfs;
    kernel = "${kernelArtifacts}/tinfoil-custom.vmlinuz";
    inherit initrd;
    repartDefinitions = ./repart.d;
  } // extraArgs);
  shippingImage = buildImage kernel.artifacts {
    basename = "tinfoilcvm";
  };
  debugImage = buildImage debugKernel.artifacts {
    debugLayer = rootfs.debugLayer;
    basename = "tinfoilcvm-debug";
  };
in
go.packages
// {
  inherit (go) checks;
  inherit initrd;
  "kernel-artifacts" = kernel.artifacts;
  "debug-kernel-artifacts" = debugKernel.artifacts;
  "nvidia-modules" = nvidia.modules;
  inherit (nvattest) nvattest;
  "rootfs-archive" = rootfs.rootfs;
  "debug-rootfs-layer" = rootfs.debugLayer;
  "runtime-package-lock" = runtimePackages.lock;
  "release-upload-cli" = pkgs.awscli2;
  "shipping-image" = shippingImage;
  "debug-image" = debugImage;
}
